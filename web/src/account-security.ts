import type { AccountFactor, AccountProfile, AccountProfileInput } from "./types";

export const accountProviders = ["Apple", "Discord", "Facebook", "GitHub", "Google", "Instagram", "LinkedIn", "Microsoft", "PlayStation", "Reddit", "Steam", "TikTok", "Twitch", "X", "YouTube"];

export const emptyAccountProfile = (): AccountProfileInput => ({
	provider: "",
	label: "",
	identifier: "",
	category: "social",
	twoStepStatus: "unknown",
	factors: [],
	passwordStatus: "unknown",
	recoveryStatus: "unknown",
	backupCodesStatus: "unknown",
	lastReviewedAt: null,
	reviewDetails: [],
	notes: "",
});

export function accountSummary(profiles: AccountProfile[]) {
	return {
		total: profiles.length,
		good: profiles.filter((profile) => profile.status === "good").length,
		attention: profiles.filter((profile) => profile.status === "attention").length,
		incomplete: profiles.filter((profile) => profile.status === "incomplete").length,
		suggestions: profiles.reduce((count, profile) => count + profile.suggestions.length, 0),
	};
}

export function statusLabel(value: string) {
	const labels: Record<string, string> = {
		unknown: "Not checked",
		enabled: "Enabled",
		disabled: "Not enabled",
		"not-supported": "Not supported",
		unique: "Unique",
		reused: "Reused",
		passwordless: "Passwordless",
		"not-applicable": "Not applicable",
		configured: "Configured",
		missing: "Not configured",
		stored: "Stored safely",
	};
	return labels[value] || value;
}

export function factorLabel(factor: AccountFactor) {
	const labels: Record<AccountFactor, string> = {
		authenticator: "Authenticator app",
		passkey: "Passkey",
		"security-key": "Security key",
		"provider-prompt": "Provider prompt",
		sms: "SMS",
		email: "Email",
		other: "Other",
	};
	return labels[factor];
}

export function dateInputValue(value?: string | null) {
	if (!value) return "";
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? "" : date.toISOString().slice(0, 10);
}

export function reviewedAtFromInput(value: string) {
	return value ? `${value}T12:00:00.000Z` : null;
}
