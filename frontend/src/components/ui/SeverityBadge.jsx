import { C, SEV_COLOR } from "../../config";

export function SeverityBadge({ sev }) {
  const color = SEV_COLOR[sev] || C.muted;
  return (
    <span style={{
      background: color + "22", color, border: `1px solid ${color}55`,
      borderRadius: 4, padding: "2px 8px", fontSize: 11,
      fontFamily: "'Share Tech Mono', monospace", fontWeight: 600,
      letterSpacing: 1, whiteSpace: "nowrap",
    }}>
      {sev}
    </span>
  );
}
