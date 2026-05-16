import { C, REFRESH_MS } from "../../config";
import { PulsingDot } from "../ui/ScanLine";

const PAGES = [
  { id: "overview",   label: "Overview",      icon: "⬡" },
  { id: "events",     label: "Live Events",   icon: "◈" },
  { id: "alerts",     label: "Alerts",        icon: "◉" },
  { id: "threatmap",  label: "Threat Map",    icon: "🌐" },
  { id: "reports",    label: "Reports",       icon: "◫" },
  { id: "settings",   label: "Settings",      icon: "⚙" },
];

export function Sidebar({ page, setPage, critCount, wsConnected }) {
  return (
    <div style={{
      position: "fixed", left: 0, top: 0, bottom: 0, width: 224,
      background: C.surface, borderRight: `1px solid ${C.border}`,
      display: "flex", flexDirection: "column", zIndex: 100,
    }}>
      {/* Logo */}
      <div style={{ padding: "24px 20px", borderBottom: `1px solid ${C.border}` }}>
        <div style={{
          fontSize: 11, color: C.muted, letterSpacing: 3,
          textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace",
        }}>◈ SIEM</div>
        <div style={{ fontSize: 20, fontWeight: 700, color: C.accent, letterSpacing: 1, marginTop: 4 }}>
          SecureWatch
        </div>
        <div style={{ fontSize: 10, color: C.muted, marginTop: 4, fontFamily: "'Share Tech Mono', monospace", display: "flex", alignItems: "center", gap: 6 }}>
          v3.0 · AI <PulsingDot color={C.green} />
        </div>
      </div>

      {/* Nav */}
      <nav style={{ padding: "16px 12px", flex: 1, overflowY: "auto" }}>
        {PAGES.map(p => {
          const active = page === p.id;
          return (
            <button key={p.id} onClick={() => setPage(p.id)}
              style={{
                display: "flex", alignItems: "center", gap: 10,
                width: "100%", padding: "10px 12px", marginBottom: 4,
                background: active ? C.accent + "18" : "transparent",
                border: `1px solid ${active ? C.accent + "44" : "transparent"}`,
                borderRadius: 8, color: active ? C.accent : C.muted,
                cursor: "pointer", fontSize: 14, fontWeight: active ? 600 : 400,
                transition: "all 0.15s", textAlign: "left",
              }}
              onMouseEnter={e => { if (!active) e.currentTarget.style.color = C.text; }}
              onMouseLeave={e => { if (!active) e.currentTarget.style.color = C.muted; }}
            >
              <span style={{ fontSize: 15 }}>{p.icon}</span>
              {p.label}
              {p.id === "alerts" && critCount > 0 && (
                <span style={{
                  marginLeft: "auto", background: C.red,
                  color: "#fff", borderRadius: 10, padding: "1px 7px",
                  fontSize: 10, fontFamily: "'Share Tech Mono', monospace",
                  animation: "pulse 2s infinite",
                }}>
                  {critCount}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <div style={{ padding: "16px 20px", borderTop: `1px solid ${C.border}` }}>
        <div style={{ fontSize: 10, color: C.muted, fontFamily: "'Share Tech Mono', monospace", lineHeight: 2 }}>
          <div>SecureWatch AI v3.0</div>
          <div style={{
            color: wsConnected ? C.green : C.yellow,
            display: "flex", alignItems: "center", gap: 5,
          }}>
            <PulsingDot color={wsConnected ? C.green : C.yellow} size={5} />
            {wsConnected ? "Real-time connected" : "Polling mode"}
          </div>
          <div style={{ marginTop: 4, color: C.muted }}>
            {wsConnected ? "WebSocket active" : `Polling: ${REFRESH_MS / 1000}s`}
          </div>
        </div>
      </div>
    </div>
  );
}

export { PAGES };
