import { C } from "../../config";

export function ScanLine() {
  return (
    <div style={{
      position: "fixed", top: 0, left: 0, right: 0, height: "2px",
      background: `linear-gradient(90deg, transparent, ${C.accent}, transparent)`,
      animation: "scanline 3s linear infinite", zIndex: 9999, opacity: 0.6,
      pointerEvents: "none",
    }} />
  );
}

export function PulsingDot({ color, size = 6 }) {
  return (
    <span style={{
      display: "inline-block", width: size, height: size,
      background: color, borderRadius: "50%",
      animation: "pulse 2s infinite",
    }} />
  );
}
