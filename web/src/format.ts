import type { ContainerPortBinding } from "./types";
import { normalizeAddress } from "./network";

export function formatDate(value: string | null | undefined, fallback = "Not reported") {
	if (!value) return fallback;
	const date = new Date(value);
	return Number.isNaN(date.valueOf()) ? fallback : date.toLocaleString();
}

export function formatRelativeTime(value: string | null | undefined, fallback = "not reported") {
	if (!value) return fallback;
	const timestamp = new Date(value).valueOf();
	if (!Number.isFinite(timestamp)) return fallback;
	const elapsedSeconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
	if (elapsedSeconds < 10) return "just now";
	if (elapsedSeconds < 60) return `${elapsedSeconds}s ago`;
	const elapsedMinutes = Math.floor(elapsedSeconds / 60);
	if (elapsedMinutes < 60) return `${elapsedMinutes} min ago`;
	const elapsedHours = Math.floor(elapsedMinutes / 60);
	if (elapsedHours < 48) return `${elapsedHours} hr ago`;
	return `${Math.floor(elapsedHours / 24)} days ago`;
}

export function formatTimeRemaining(value: string) {
	const remainingSeconds = Math.max(0, Math.ceil((new Date(value).valueOf() - Date.now()) / 1000));
	if (remainingSeconds < 60) return "less than 1 min";
	const minutes = Math.ceil(remainingSeconds / 60);
	if (minutes < 60) return `${minutes} min`;
	const hours = Math.ceil(minutes / 60);
	if (hours < 48) return `${hours} hr`;
	return `${Math.ceil(hours / 24)} days`;
}

export function formatDuration(value: number | null) {
	if (value === null || !Number.isFinite(value)) return "Uptime unavailable";
	const totalHours = Math.floor(value / 3600);
	const days = Math.floor(totalHours / 24);
	const hours = totalHours % 24;
	return days > 0 ? `${days}d ${hours}h uptime` : `${hours}h uptime`;
}

export function formatInterval(seconds: number) {
	if (seconds < 60) return `${seconds}s`;
	const minutes = Math.round(seconds / 60);
	return minutes < 60 ? `${minutes} min` : `${Math.round(minutes / 60)} hr`;
}

export function formatBytes(value: number | null | undefined) {
	if (value === null || value === undefined || !Number.isFinite(value)) return "Not reported";
	const units = ["B", "KiB", "MiB", "GiB", "TiB"];
	let size = Math.max(0, value);
	let unit = 0;
	while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
	return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

export function booleanValue(value: boolean | null) {
	if (value === true) return { label: "On", className: "value-good" };
	if (value === false) return { label: "Off", className: "value-bad" };
	return { label: "Unavailable", className: "value-muted" };
}

export function formatPortBinding(binding: ContainerPortBinding) {
	if (!binding.published) return `${binding.containerPort}/${binding.protocol.toLowerCase()} · container only`;
	const address = normalizeAddress(binding.hostAddress || "") || "*";
	const host = address.includes(":") ? `[${address}]` : address;
	return `${host}:${binding.hostPort} → ${binding.containerPort}/${binding.protocol.toLowerCase()}`;
}

export function policyValue(value?: string) {
	return !value || value === "NotConfigured" ? "System default" : value;
}
