import type { ReactNode } from "react";

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
  return <SvgIcon {...props}><path d="M12 2.7 20 6v5.8c0 4.9-3.1 8-8 9.5-4.9-1.5-8-4.6-8-9.5V6l8-3.3Z" /><path d="M8.5 8.1v7.8M15.5 8.1v7.8M8.5 12h7" /></SvgIcon>;
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
