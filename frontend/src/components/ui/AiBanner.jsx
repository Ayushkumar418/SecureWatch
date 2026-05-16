import { C } from "../../config";

export function AiBanner({ status }) {
  if (!status?.banner) return null;
  const { type, message } = status.banner;
  const colors = {
    success: { bg: "#00e67611", border: C.green,  text: C.green  },
    warning: { bg: "#ffd60011", border: C.yellow, text: C.yellow },
    error:   { bg: "#ff174411", border: C.red,    text: C.red    },
    info:    { bg: "#00d4ff11", border: C.accent, text: C.accent },
  };
  const s = colors[type] || colors.info;
  const icon = type === "success" ? "✅" : type === "warning" ? "⚠️" : type === "error" ? "❌" : "ℹ️";
  return (
    <div style={{
      background: s.bg, border: `1px solid ${s.border}`,
      borderRadius: 8, padding: "10px 16px", marginBottom: 20,
      color: s.text, fontSize: 13,
      fontFamily: "'Share Tech Mono', monospace",
      display: "flex", alignItems: "center", gap: 10,
    }}>
      <span style={{ fontSize: 16 }}>{icon}</span>
      <span>{message}</span>
    </div>
  );
}
