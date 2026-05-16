import { C } from "../../config";

export function StatCard({ label, value, sub, color = C.accent, icon, trend }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${C.border}`,
      borderRadius: 12, padding: "20px 24px",
      borderTop: `3px solid ${color}`, position: "relative", overflow: "hidden",
      transition: "transform 0.2s, box-shadow 0.2s",
    }}
      onMouseEnter={e => {
        e.currentTarget.style.transform = "translateY(-2px)";
        e.currentTarget.style.boxShadow = `0 8px 32px ${color}22`;
      }}
      onMouseLeave={e => {
        e.currentTarget.style.transform = "translateY(0)";
        e.currentTarget.style.boxShadow = "none";
      }}
    >
      <div style={{
        position: "absolute", top: 12, right: 16,
        fontSize: 28, opacity: 0.12,
      }}>{icon}</div>
      <div style={{
        fontSize: 11, color: C.muted, textTransform: "uppercase",
        letterSpacing: 1.5, fontFamily: "'Share Tech Mono', monospace",
      }}>
        {label}
      </div>
      <div style={{
        fontSize: 38, fontWeight: 700, color, fontFamily: "'Share Tech Mono', monospace",
        lineHeight: 1.2, marginTop: 6,
      }}>
        {value ?? "—"}
      </div>
      {sub && (
        <div style={{ fontSize: 11, color: C.muted, marginTop: 4 }}>{sub}</div>
      )}
      {trend !== undefined && (
        <div style={{
          position: "absolute", bottom: 10, right: 14,
          fontSize: 10, fontFamily: "'Share Tech Mono', monospace",
          color: trend > 0 ? C.red : C.green,
        }}>
          {trend > 0 ? `▲ +${trend}` : `▼ ${trend}`} vs last hour
        </div>
      )}
    </div>
  );
}
