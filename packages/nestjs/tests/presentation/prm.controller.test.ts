import { describe, expect, it } from "vitest";

import { buildPrmController } from "../../src/presentation/prm.controller.js";
import { AUTHPLANE_RESOURCE } from "../../src/module/authplane.tokens.js";
import {
	METADATA_KEY_SKIP_AUTH,
} from "../../src/application/metadata-keys.js";

describe("buildPrmController", () => {
	const STUB_METADATA = {
		resource: "https://api.example.com/mcp",
		authorization_servers: ["https://auth.example.com"],
	};

	function stubResource(body: unknown = STUB_METADATA) {
		return {
			prmResponse: () => body,
			prmDocumentUrl: () =>
				"https://api.example.com/.well-known/oauth-protected-resource/mcp",
		};
	}

	it("returns a NestJS @Controller class", () => {
		const PrmController = buildPrmController(
			"/.well-known/oauth-protected-resource/mcp",
		);
		expect(typeof PrmController).toBe("function");
		expect(PrmController.name).toBe("AuthplanePrmController");
	});

	it("serves the prmResponse() payload from the injected resource", () => {
		const PrmController = buildPrmController(
			"/.well-known/oauth-protected-resource/mcp",
		);
		const instance = new (PrmController as new (r: unknown) => { serve(): unknown })(
			stubResource(),
		);
		expect(instance.serve()).toEqual(STUB_METADATA);
	});

	it("marks the serve() handler as public via @SkipAuth()", () => {
		const PrmController = buildPrmController(
			"/.well-known/oauth-protected-resource/mcp",
		);
		const proto = (PrmController as unknown as { prototype: Record<string, unknown> })
			.prototype;
		const skipFlag = Reflect.getMetadata(METADATA_KEY_SKIP_AUTH, proto.serve as object);
		expect(skipFlag).toBe(true);
	});

	it("bakes the supplied path into the route metadata on serve()", () => {
		const PrmController = buildPrmController(
			"/.well-known/oauth-protected-resource/mcp",
		);
		const proto = (PrmController as unknown as { prototype: Record<string, unknown> })
			.prototype;
		const routePath = Reflect.getMetadata("path", proto.serve as object);
		expect(routePath).toBe("/.well-known/oauth-protected-resource/mcp");
	});

	it("declares AUTHPLANE_RESOURCE as the injected constructor arg", () => {
		const PrmController = buildPrmController(
			"/.well-known/oauth-protected-resource/mcp",
		);
		const paramTypes = Reflect.getMetadata(
			"self:paramtypes",
			PrmController,
		) as Array<{ index: number; param: symbol | undefined }> | undefined;
		const injected = paramTypes?.[0]?.param;
		expect(injected).toBe(AUTHPLANE_RESOURCE);
	});
});
