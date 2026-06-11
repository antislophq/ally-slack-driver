/*
|--------------------------------------------------------------------------
| Ally Oauth driver
|--------------------------------------------------------------------------
|
| Slack "Sign in with Slack" OpenID Connect driver.
|
*/

import { Oauth2Driver, RedirectRequest } from '@adonisjs/ally'
import type { HttpContext } from '@adonisjs/core/http'
import type {
  AllyDriverContract,
  AllyUserContract,
  ApiRequestContract,
} from '@adonisjs/ally/types'
import { randomBytes } from 'node:crypto'

/**
 * Response from 
 * https://docs.slack.dev/reference/methods/openid.connect.token/#response
 */
export type SlackAccessToken = {
  token: string
  type: 'bearer'
  id_token: string
}

/**
 * Scopes accepted by the Slack OpenID Connect driver.
 * https://slack.com/.well-known/openid-configuration
 */
export type SlackScopes = 'openid' | 'profile' | 'email'

/**
 * Configuration accepted by the Slack driver.
 */
export type SlackDriverConfig = {
  clientId: string
  clientSecret: string
  callbackUrl: string
  scopes?: SlackScopes[] // default: ['openid', 'profile', 'email']
  team?: string
}

type AllyUser = {
  id: string
  nickName: string
  name: string
  email: string | null
  avatarUrl: string | null
  emailVerificationState: 'verified' | 'unverified'
  original: SlackUser
}

type SlackUser = {
  sub: string
  name?: string | null
  email?: string | null
  email_verified?: boolean | null
  picture?: string | null
  'https://slack.com/user_image_512'?: string | null
  [key: string]: unknown
}

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const segments = jwt.split('.')
  if (segments.length < 2 || !segments[1]) {
    throw new Error('Invalid id_token: missing JWT payload')
  }

  try {
    return JSON.parse(Buffer.from(segments[1], 'base64url').toString())
  } catch {
    throw new Error('Invalid id_token: malformed JWT payload')
  }
}

function toAllyUser(user: SlackUser): AllyUser {
  if (!user.sub) {
    throw new Error('Slack OIDC claims missing user id')
  }

  return {
    id: user.sub,
    nickName: user.name ?? '',
    name: user.name ?? '',
    email: user.email ?? null,
    emailVerificationState: user.email_verified ? 'verified' : 'unverified',
    avatarUrl: user.picture ?? user['https://slack.com/user_image_512'] ?? null,
    original: user,
  } satisfies Omit<AllyUserContract<SlackAccessToken>, 'token'>
}

function toSlackUser(payload: Record<string, unknown>): SlackUser {
  const keysToRemove = [
    'iss',
    'aud',
    'exp',
    'iat',
    'auth_time',
    'nonce',
    'at_hash',
    'ok',
    'error',
  ] as const

  for (const key of keysToRemove) {
    delete payload[key]
  }

  return payload as SlackUser
}

/**
 * Driver implementation for Slack Sign in with Slack (OpenID Connect).
 */
export class SlackDriver
  extends Oauth2Driver<SlackAccessToken, SlackScopes>
  implements AllyDriverContract<SlackAccessToken, SlackScopes> {

  // https://slack.com/.well-known/openid-configuration
  protected authorizeUrl = 'https://slack.com/openid/connect/authorize'
  protected accessTokenUrl = 'https://slack.com/api/openid.connect.token'
  protected userInfoUrl = 'https://slack.com/api/openid.connect.userInfo'

  protected codeParamName = 'code'
  protected errorParamName = 'error'

  protected stateCookieName = 'slack_oauth_state'
  protected stateParamName = 'state'
  protected scopeParamName = 'scope'
  protected scopesSeparator = ' '

  protected nonceCookieName = 'slack_oauth_nonce'
  protected nonceCookieValue?: string

  constructor(
    ctx: HttpContext,
    public config: SlackDriverConfig
  ) {
    super(ctx, config)
    this.loadState()
    this.nonceCookieValue = this.ctx.request.encryptedCookie(this.nonceCookieName)
    this.ctx.response.clearCookie(this.nonceCookieName)
  }

  /**
   * Configures the authorization redirect for Slack OpenID Connect.
   */
  protected configureRedirectRequest(request: RedirectRequest<SlackScopes>) {
    const scopes = this.config.scopes ?? ['openid', 'profile', 'email']

    if (!scopes.includes('openid')) {
      throw new Error('Sign in with Slack requires the openid scope')
    }

    request.scopes(scopes)
    request.param('response_type', 'code')

    const nonce = randomBytes(16).toString('hex')
    this.ctx.response.encryptedCookie(this.nonceCookieName, nonce, {
      sameSite: false,
      httpOnly: true,
    })
    request.param('nonce', nonce)

    if (this.config.team) {
      request.param('team', this.config.team)
    }
  }

  /**
   * Returns an HTTP client with the Bearer authorization header set.
   */
  protected getAuthenticatedRequest(url: string, token: string) {
    const request = this.httpClient(url)
    request.header('Authorization', `Bearer ${token}`)
    request.header('Accept', 'application/json')
    request.parseAs('json')
    return request
  }

  protected decodeIdToken(idToken: string): SlackUser {
    const payload = decodeJwtPayload(idToken)

    if (payload.nonce !== this.nonceCookieValue) {
      throw new Error('OpenID Connect nonce mismatch')
    }

    if (payload.aud !== this.config.clientId) {
      throw new Error('OpenID Connect audience mismatch')
    }

    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new Error('OpenID Connect id_token missing sub')
    }

    return toSlackUser(payload)
  }

  /**
   * Fetches user info from the Slack OpenID Connect userInfo endpoint.
   */
  protected async getUserInfo(token: string, callback?: (request: ApiRequestContract) => void) {
    const request = this.getAuthenticatedRequest(this.userInfoUrl, token)

    if (typeof callback === 'function') {
      callback(request)
    }

    const body = (await request.post()) as Record<string, unknown>

    if (body.ok === false) {
      throw new Error(
        typeof body.error === 'string' ? body.error : 'Slack userInfo request failed'
      )
    }

    return toAllyUser(toSlackUser(body))
  }

  /**
   * Exchanges the authorization code for access_token and id_token that decodes to a SlackUser.
   */
  async accessToken(
    callback?: (request: ApiRequestContract) => void
  ): Promise<SlackAccessToken> {
    return await super.accessToken(callback)
  }

  /**
   * Returns true when the user denied access during the OAuth redirect.
   */
  accessDenied() {
    const error = this.getError()
    if (!error) {
      return false
    }
    return error === 'access_denied'
  }

  /**
   * Gets the authenticated user and access token after the OAuth callback.
   */
  async user(
    callback?: (request: ApiRequestContract) => void
  ): Promise<AllyUserContract<SlackAccessToken>> {
    const accessToken = await this.accessToken(callback)
    const slackUser = this.decodeIdToken(accessToken.id_token)
    const user = toAllyUser(slackUser)

    return {
      ...user,
      token: accessToken,
    }
  }

  /**
   * Gets the authenticated user from an existing access token.
   */
  async userFromToken(
    accessToken: string,
    callback?: (request: ApiRequestContract) => void
  ): Promise<AllyUserContract<{ token: string; type: 'bearer' }>> {
    const user = await this.getUserInfo(accessToken, callback)

    return {
      ...user,
      token: { token: accessToken, type: 'bearer' },
    }
  }
}

/**
 * Factory function to reference the driver inside config/ally.ts.
 */
export function SlackDriverService(config: SlackDriverConfig): (ctx: HttpContext) => SlackDriver {
  return (ctx) => new SlackDriver(ctx, config)
}
