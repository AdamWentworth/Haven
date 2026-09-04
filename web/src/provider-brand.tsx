import {
	siApple,
	siDiscord,
	siFacebook,
	siGithub,
	siGoogle,
	siInstagram,
	siPlaystation,
	siReddit,
	siSteam,
	siTiktok,
	siTwitch,
	siX,
	siYoutube,
	type SimpleIcon,
} from "simple-icons";

const icons: Record<string, SimpleIcon> = {
	apple: siApple,
	discord: siDiscord,
	facebook: siFacebook,
	github: siGithub,
	google: siGoogle,
	instagram: siInstagram,
	playstation: siPlaystation,
	reddit: siReddit,
	steam: siSteam,
	tiktok: siTiktok,
	twitch: siTwitch,
	x: siX,
	youtube: siYoutube,
};

const visibleColors: Record<string, string> = {
	apple: "#f5f5f7",
	github: "#f0f6fc",
	playstation: "#67a3ff",
	steam: "#66c0f4",
	tiktok: "#f2f2f2",
	x: "#f2f2f2",
};

function MicrosoftBrand() {
	return <span className="microsoft-brand" aria-hidden="true"><i /><i /><i /><i /></span>;
}

function LinkedInBrand() {
	return <span className="linkedin-brand" aria-hidden="true">in</span>;
}

export function ProviderBrand({ provider }: { provider: string }) {
	const key = provider.toLowerCase().replaceAll(/[^a-z0-9]/g, "");
	if (key === "microsoft") return <span className="account-avatar branded" data-provider-brand="Microsoft"><MicrosoftBrand /></span>;
	if (key === "linkedin") return <span className="account-avatar branded" data-provider-brand="LinkedIn"><LinkedInBrand /></span>;
	const icon = icons[key];
	if (icon) {
		return <span className="account-avatar branded" data-provider-brand={icon.title} style={{ color: visibleColors[key] || `#${icon.hex}` }} aria-hidden="true"><svg viewBox="0 0 24 24" role="img"><path fill="currentColor" d={icon.path} /></svg></span>;
	}
	const monogram = provider.trim().split(/\s+/).map((word) => word[0]).join("").slice(0, 2).toUpperCase() || "?";
	return <span className="account-avatar" data-provider-brand="custom" aria-hidden="true">{monogram}</span>;
}
