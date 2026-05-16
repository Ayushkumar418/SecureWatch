// ── Global config ──────────────────────────────────────────────────────────
// Set VITE_API_URL in frontend/.env to point at your backend.
// Default: http://localhost:5000/api
export const API = import.meta.env.VITE_API_URL ?? "http://localhost:5000/api";
export const REFRESH_MS = 10_000; // auto-refresh interval

// ── Design tokens ──────────────────────────────────────────────────────────
export const C = {
  bg:      "#0a0e1a",
  surface: "#0f1628",
  card:    "#131c35",
  border:  "#1e2d50",
  accent:  "#00d4ff",
  green:   "#00e676",
  yellow:  "#ffd600",
  orange:  "#ff6d00",
  red:     "#ff1744",
  purple:  "#7c4dff",
  text:    "#e8f0fe",
  muted:   "#5c7099",
};

export const SEV_COLOR = {
  CRITICAL: C.red,
  HIGH:     C.orange,
  MEDIUM:   C.yellow,
  LOW:      C.green,
  INFO:     C.accent,
  WARNING:  C.yellow,
  ERROR:    C.orange,
  DEBUG:    C.muted,
};

// ── Shared helpers ──────────────────────────────────────────────────────────
export function timeAgo(iso) {
  const diff = Date.now() - new Date(iso);
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
