import { useId, type ReactNode } from "react";

interface IconProps {
  className?: string;
  size?: number;
}

function SvgIcon({ children, className, size = 22 }: IconProps & { children: ReactNode }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      {children}
    </svg>
  );
}

export function HavenIcon(props: IconProps) {
  const { className, size = 22 } = props;
  const id = useId().replace(/:/g, "");
  const rim = `${id}-haven-rim`;
  const field = `${id}-haven-field`;
  const monogram = `${id}-haven-h`;
  return <svg className={className} width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <defs>
      <linearGradient id={rim} x1="4" y1="3" x2="20" y2="21" gradientUnits="userSpaceOnUse"><stop stopColor="#04dc8b" /><stop offset="1" stopColor="#05b5dc" /></linearGradient>
      <linearGradient id={field} x1="12" y1="3" x2="12" y2="21" gradientUnits="userSpaceOnUse"><stop stopColor="#071924" /><stop offset="1" stopColor="#05222e" /></linearGradient>
      <linearGradient id={monogram} x1="12" y1="6" x2="12" y2="18.5" gradientUnits="userSpaceOnUse"><stop stopColor="#56eba4" /><stop offset="1" stopColor="#0fcfe0" /></linearGradient>
    </defs>
    <path d="M12 1.7C10.6 2.85 8.4 4.05 4.1 5.12 3.7 5.22 3.48 5.58 3.48 6.02V10.4C3.48 15.6 6.35 19.25 11.58 21.58Q12 21.77 12.42 21.58C17.65 19.25 20.52 15.6 20.52 10.4V6.02C20.52 5.58 20.3 5.22 19.9 5.12 15.6 4.05 13.4 2.85 12 1.7Z" fill={`url(#${rim})`} />
    <path d="M12 2.9C10.85 3.82 8.75 4.85 5.05 5.82 4.75 5.9 4.58 6.17 4.58 6.5V10.4C4.58 15.05 7.04 18.22 11.62 20.47Q12 20.66 12.38 20.47C16.96 18.22 19.42 15.05 19.42 10.4V6.5C19.42 6.17 19.25 5.9 18.95 5.82 15.25 4.85 13.15 3.82 12 2.9Z" fill="#e0fff8" />
    <path d="M12 3.14C10.88 4.02 8.83 5.02 5.29 5.95 5.07 6.01 4.94 6.21 4.94 6.46V10.4C4.94 14.86 7.27 17.88 11.68 20.06Q12 20.22 12.32 20.06C16.73 17.88 19.06 14.86 19.06 10.4V6.46C19.06 6.21 18.93 6.01 18.71 5.95 15.17 5.02 13.12 4.02 12 3.14Z" fill={`url(#${field})`} />
    <path d="M7.55 7 9.45 5.92 9.62 6.02V10.25H14.38V6.02L14.55 5.92 16.45 7 16.58 7.25V16.55L16.45 16.82 14.55 18.22 14.38 18.45V12.55H9.62V18.45L9.45 18.22 7.55 16.82 7.42 16.55V7.25L7.55 7Z" fill={`url(#${monogram})`} />
  </svg>;
}

export function DefenderIcon(props: IconProps) {
  return <SvgIcon {...props}><path d="M12 2.7 20 6v5.8c0 4.9-3.1 8-8 9.5-4.9-1.5-8-4.6-8-9.5V6l8-3.3Z" /><path d="M12 5.1v13.6M5.5 11.1h13" /></SvgIcon>;
}

export function FirewallIcon(props: IconProps) {
  return <SvgIcon {...props}><path d="M3 5h18v14H3zM3 10h18M3 15h18M8 5v5M16 5v5M6 10v5M14 10v5M10 15v4M18 15v4" /></SvgIcon>;
}

export function NetworkIcon(props: IconProps) {
  return <SvgIcon {...props}><circle cx="12" cy="5" r="2.3" /><circle cx="5" cy="18" r="2.3" /><circle cx="19" cy="18" r="2.3" /><path d="m10.9 7-4.7 8.9M13.1 7l4.7 8.9M7.3 18h9.4" /></SvgIcon>;
}

export function BrowserIcon(props: IconProps) {
  return <SvgIcon {...props}><circle cx="12" cy="12" r="9" /><path d="M3 9h18M8 3.8C9.6 6 10.4 8.8 10.4 12S9.6 18 8 20.2M16 3.8c-1.6 2.2-2.4 5-2.4 8.2s.8 6 2.4 8.2M3.8 15h16.4" /></SvgIcon>;
}

export function DevicesIcon(props: IconProps) {
  return <SvgIcon {...props}><rect x="3" y="4" width="13" height="10" rx="1.5" /><path d="M7 19h12a2 2 0 0 0 2-2V9M9.5 14v3M6.5 17h6" /></SvgIcon>;
}

export function MonitorIcon(props: IconProps) {
  return <SvgIcon {...props}><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></SvgIcon>;
}

export function LaptopIcon(props: IconProps) {
  return <SvgIcon {...props}><rect x="5" y="4" width="14" height="11" rx="1.5" /><path d="m3 19 2-4h14l2 4H3Z" /></SvgIcon>;
}

export function ServerIcon(props: IconProps) {
  return <SvgIcon {...props}><rect x="4" y="3" width="16" height="7" rx="1.5" /><rect x="4" y="14" width="16" height="7" rx="1.5" /><path d="M8 6.5h.01M8 17.5h.01M12 6.5h5M12 17.5h5" /></SvgIcon>;
}

export function WorkloadIcon(props: IconProps) {
  return <SvgIcon {...props}><path d="m12 2.8 7 3.5-7 3.5-7-3.5 7-3.5Z" /><path d="m5 6.3v7l7 3.5 7-3.5v-7M12 9.8v7" /><path d="m8 14.8-3 1.5 7 3.5 7-3.5-3-1.5" /></SvgIcon>;
}

export function AlertIcon(props: IconProps) {
  return <SvgIcon {...props}><path d="M10.3 3.8 2.7 17a2 2 0 0 0 1.7 3h15.2a2 2 0 0 0 1.7-3L13.7 3.8a2 2 0 0 0-3.4 0Z" /><path d="M12 9v4M12 17h.01" /></SvgIcon>;
}

export function RefreshIcon(props: IconProps) {
  return <SvgIcon {...props}><path d="M20 7v5h-5M4 17v-5h5" /><path d="M6.1 8.1A7 7 0 0 1 18.4 7L20 12M4 12l1.6 5A7 7 0 0 0 17.9 16" /></SvgIcon>;
}

export function CheckIcon(props: IconProps) {
  return <SvgIcon {...props}><circle cx="12" cy="12" r="9" /><path d="m8 12 2.6 2.7L16.5 9" /></SvgIcon>;
}

export function HelpIcon(props: IconProps) {
  return <SvgIcon {...props}><circle cx="12" cy="12" r="9" /><path d="M9.8 9a2.4 2.4 0 1 1 3.1 2.3c-.9.3-.9 1-.9 1.7M12 17h.01" /></SvgIcon>;
}

export function UpdateIcon(props: IconProps) {
  return <SvgIcon {...props}><path d="M20 7v5h-5M4 17v-5h5" /><path d="M6.1 8.1A7 7 0 0 1 18.4 7L20 12M4 12l1.6 5A7 7 0 0 0 17.9 16" /></SvgIcon>;
}

export function LockIcon(props: IconProps) {
  return <SvgIcon {...props}><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" /></SvgIcon>;
}

export function ChipIcon(props: IconProps) {
  return <SvgIcon {...props}><rect x="6" y="6" width="12" height="12" rx="2" /><path d="M9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3M9.5 9.5h5v5h-5z" /></SvgIcon>;
}

export function RemoteAccessIcon(props: IconProps) {
  return <SvgIcon {...props}><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4M8 10h8M13 7l3 3-3 3" /></SvgIcon>;
}

export function UsersIcon(props: IconProps) {
  return <SvgIcon {...props}><circle cx="9" cy="8" r="3" /><path d="M3.5 20v-2a5.5 5.5 0 0 1 11 0v2M16 5.5a3 3 0 0 1 0 5.8M17 14a5 5 0 0 1 3.5 4.8V20" /></SvgIcon>;
}

export function ActivityIcon(props: IconProps) {
  return <SvgIcon {...props}><path d="M3 12h4l2.2-6 4.1 12 2.1-6H21" /></SvgIcon>;
}

export function BellIcon(props: IconProps) {
  return <SvgIcon {...props}><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" /></SvgIcon>;
}

export function SettingsIcon(props: IconProps) {
  return <SvgIcon {...props}><path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h7M15 18h5" /><circle cx="16" cy="6" r="2" /><circle cx="8" cy="12" r="2" /><circle cx="13" cy="18" r="2" /></SvgIcon>;
}
