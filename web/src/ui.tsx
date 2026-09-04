export type Tone = "healthy" | "configured" | "attention" | "danger" | "unknown";
export type Accent = "green" | "blue" | "amber" | "cyan";

export function StatusChip({ label, tone }: { label: string; tone: Tone }) {
	return <span className={`status-chip ${tone}`}>{label}</span>;
}
