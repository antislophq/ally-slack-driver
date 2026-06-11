# AdonisJS Ally Slack Driver

[![NPM version](https://img.shields.io/npm/v/@antislop/ally-slack.svg)](https://www.npmjs.com/package/@antislop/ally-slack)

A [Sign in with Slack](https://docs.slack.dev/authentication/sign-in-with-slack/) (OpenID Connect) driver for [AdonisJS Ally](https://docs.adonisjs.com/guides/auth/social-authentication).

## Installation

```bash
npm install @antislop/ally-slack
```

`@adonisjs/core` and `@adonisjs/ally` are peer dependencies. You should already have them installed.


## Usage

Import and use `SlackDriverService` in your `config/ally.ts` file:

```ts
import { defineConfig } from "@adonisjs/ally";
import { SlackDriverService } from "@antislop/ally-slack";

const allyConfig = defineConfig({
  slack: SlackDriverService({
    clientId: ...,
    clientSecret: ...,
    callbackUrl: ...,
    scopes: ['openid', 'profile', 'email'],
  }),
});
```

## Scopes

Slack OpenID Connect supports:

| Scope | Description |
| --- | --- |
| `openid` | Required for Sign in with Slack |
| `profile` | (Optional) Name and profile images |
| `email`   | (Optional) Email address |

If left unspecified, the default scopes incluse all of the above.  

## License

[MIT](LICENSE)