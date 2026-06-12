# @authplane/nestjs

[Authplane](https://github.com/AuthPlane/authserver) JWT validation adapter for the [NestJS](https://nestjs.com) framework. Bearer-token auth on your NestJS app in a single `Module` import — works on both `@nestjs/platform-express` and `@nestjs/platform-fastify`.

## Install

```bash
npm install @authplane/sdk @authplane/nestjs @nestjs/common @nestjs/core reflect-metadata rxjs
```

## Quickstart

```ts
import "reflect-metadata";
import { Body, Controller, Module, Post, UseGuards } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import {
  AuthInfo,
  AuthplaneAuthGuard,
  AuthplaneModule,
  RequireScopes,
  type VerifiedClaims,
} from "@authplane/nestjs";

@Controller("mcp/tools")
@UseGuards(AuthplaneAuthGuard)
class WeatherController {
  @Post("get_weather")
  @RequireScopes("tools/get_weather")
  async getWeather(
    @AuthInfo() info: VerifiedClaims,
    @Body() body: { city: string },
  ) {
    return { content: [{ type: "text", text: `${body.city}: sunny` }] };
  }
}

@Module({
  imports: [
    AuthplaneModule.forRoot({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      scopes: ["tools/get_weather"],
    }),
  ],
  controllers: [WeatherController],
})
class AppModule {}

const app = await NestFactory.create(AppModule);
app.enableShutdownHooks(); // so AuthplaneShutdownHook runs on exit
await app.listen(3000);
```

`AuthplaneAuthGuard` validates the bearer token, enforces scopes, and attaches the verified claims to the request. Read them in a handler via `@AuthInfo()`. `@RequireScopes("…")` layers per-route scope checks on top. The RFC 9728 Protected Resource Metadata document is published automatically at the derived well-known path.

## Learn more

- **[User Guide](docs/user-guide.md)** — complete reference: module options, scope enforcement, DPoP, introspection and revocation, Express-vs-Fastify notes, error handling, runtime portability.
- **[Demo](demo/README.md)** — runnable multi-route calculator (`./demo/run.sh`).
- **[`@authplane/sdk`](../sdk)** — the underlying OAuth/JWT primitives.

Call `app.enableShutdownHooks()` so `AuthplaneShutdownHook` can run `await client.close()` on exit — it stops internal JWKS / metadata refresh timers.
