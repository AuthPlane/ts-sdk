export interface FetchSettingsInit {
	ssrfProtection?: boolean;
	allowHttp?: boolean;
	allowLocalhost?: boolean;
	allowPrivateNetworks?: boolean;
	timeoutSeconds?: number;
}

/** OAuth protocol primitive fetch configuration. */
export class FetchSettings {
	public readonly ssrfProtection: boolean;
	public readonly allowHttp: boolean;
	public readonly allowLocalhost: boolean;
	public readonly allowPrivateNetworks: boolean;
	public readonly timeoutSeconds: number;

	public constructor(init: FetchSettingsInit = {}) {
		this.ssrfProtection = init.ssrfProtection ?? true;
		this.allowHttp = init.allowHttp ?? false;
		this.allowLocalhost = init.allowLocalhost ?? false;
		this.allowPrivateNetworks = init.allowPrivateNetworks ?? false;
		this.timeoutSeconds = init.timeoutSeconds ?? 10;
	}

	public static fromDevMode(devMode: boolean): FetchSettings {
		return new FetchSettings({
			ssrfProtection: !devMode,
			allowHttp: devMode,
			allowLocalhost: devMode,
			allowPrivateNetworks: devMode,
			timeoutSeconds: 10,
		});
	}
}
