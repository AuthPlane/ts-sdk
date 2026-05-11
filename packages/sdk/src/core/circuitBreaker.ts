import { CircuitOpenError } from "./errors.js";

export class CircuitBreaker {
	private readonly threshold: number;
	private readonly cooldownSeconds: number;

	private failures = 0;
	private openUntilSeconds: number | null = null;

	public constructor(threshold = 5, cooldownSeconds = 30) {
		this.threshold = threshold;
		this.cooldownSeconds = cooldownSeconds;
	}

	private nowSeconds(): number {
		return Math.floor(Date.now() / 1000);
	}

	public assertClosed(): void {
		if (this.openUntilSeconds === null) {
			return;
		}
		if (this.nowSeconds() >= this.openUntilSeconds) {
			this.openUntilSeconds = null;
			this.failures = 0;
			return;
		}
		throw new CircuitOpenError();
	}

	public recordSuccess(): void {
		this.failures = 0;
		this.openUntilSeconds = null;
	}

	public recordFailure(): void {
		this.failures += 1;
		if (this.failures >= this.threshold) {
			this.openUntilSeconds = this.nowSeconds() + this.cooldownSeconds;
		}
	}
}
