import { useState } from "react";
import { API, C, SEV_COLOR, timeAgo } from "../config";
import { useFetch } from "../hooks/useFetch";
import { SeverityBadge } from "../components/ui/SeverityBadge";

const filterStyle = {
  background: C.surface, border: `1px solid ${C.border}`,
  borderRadius: 6, padding: "6px 12px", color: C.text,
  fontSize: 13, fontFamily: "'Share Tech Mono', monospace", outline: "none",
};

export default function Alerts() {
  const [expanded, setExpanded]       = useState(null);
  const [resolving, setResolving]     = useState(null);
  const [showResolved, setShowRes]    = useState(false);
  const [sevFilter, setSevFilter]     = useState("");

  const url = `${API}/alerts?resolved=${showResolved}` + (sevFilter ? `&severity=${sevFilter}` : "");
  const { data, reload } = useFetch(url, [showResolved, sevFilter]);
  const alerts = data?.alerts || [];

  async function resolveAlert(id) {
    setResolving(id);
    try {
      await fetch(`${API}/alerts/${id}/resolve`, { method: "POST" });
      reload();
    } finally {
      setResolving(null);
    }
  }

  return (
    <div>
      {/* Controls */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16, alignItems: "center" }}>
        <select style={filterStyle} value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
          <option value="">All Severities</option>
          {["CRITICAL","HIGH","MEDIUM","LOW"].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <button onClick={() => setShowRes(r => !r)}
          style={{
            background: showResolved ? C.green + "22" : C.surface,
            border: `1px solid ${showResolved ? C.green : C.border}`,
            color: showResolved ? C.green : C.muted,
            borderRadius: 6, padding: "6px 14px", cursor: "pointer",
            fontFamily: "'Share Tech Mono', monospace", fontSize: 13,
          }}>
          {showResolved ? "✅ Showing Resolved" : "Show Resolved"}
        </button>
        <span style={{ color: C.muted, fontSize: 12, fontFamily: "'Share Tech Mono', monospace", marginLeft: "auto" }}>
          {alerts.length} alert{alerts.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Alert cards */}
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {alerts.length === 0 ? (
          <div style={{ textAlign: "center", padding: 60, color: C.muted, fontFamily: "'Share Tech Mono', monospace" }}>
            {showResolved ? "No resolved alerts" : "✅ No active alerts — system secure"}
          </div>
        ) : alerts.map(alert => {
          const isOpen = expanded === alert.id;
          const color  = SEV_COLOR[alert.severity] || C.muted;
          return (
            <div key={alert.id} style={{
              background: C.card, border: `1px solid ${C.border}`,
              borderLeft: `4px solid ${color}`,
              borderRadius: 10, overflow: "hidden",
              transition: "box-shadow 0.2s",
              boxShadow: isOpen ? `0 4px 20px ${color}22` : "none",
            }}>
              {/* Header row */}
              <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 18px", cursor: "pointer" }}
                onClick={() => setExpanded(isOpen ? null : alert.id)}>
                <SeverityBadge sev={alert.severity} />
                <div style={{ flex: 1 }}>
                  <div style={{ color: C.text, fontSize: 14, fontWeight: 500 }}>{alert.title}</div>
                  <div style={{ color: C.muted, fontSize: 12, marginTop: 2, fontFamily: "'Share Tech Mono', monospace" }}>
                    {alert.rule_name} · {alert.event_count} event{alert.event_count !== 1 ? "s" : ""}
                    · {timeAgo(alert.created_at)}
                    {(alert.related_ips || []).length > 0 && ` · IP: ${alert.related_ips.join(", ")}`}
                  </div>
                </div>
                <span style={{ color: C.muted, fontSize: 18, transition: "transform 0.2s", transform: isOpen ? "rotate(180deg)" : "rotate(0deg)" }}>▼</span>
                {!alert.is_resolved && (
                  <button
                    onClick={e => { e.stopPropagation(); resolveAlert(alert.id); }}
                    disabled={resolving === alert.id}
                    style={{
                      background: C.green + "22", border: `1px solid ${C.green}55`,
                      color: C.green, borderRadius: 6, padding: "4px 12px",
                      cursor: "pointer", fontSize: 12,
                      fontFamily: "'Share Tech Mono', monospace",
                    }}>
                    {resolving === alert.id ? "..." : "✓ Resolve"}
                  </button>
                )}
              </div>

              {/* Expanded: AI explanation */}
              {isOpen && (
                <div style={{ borderTop: `1px solid ${C.border}`, padding: "16px 18px", background: C.surface + "88" }}>
                  {alert.ai_explanation ? (
                    <pre style={{
                      fontFamily: "'Share Tech Mono', monospace",
                      fontSize: 13, color: C.text, whiteSpace: "pre-wrap",
                      lineHeight: 1.8, margin: 0,
                    }}>
                      {alert.ai_explanation}
                    </pre>
                  ) : (
                    <div style={{ color: C.muted, fontSize: 13, fontFamily: "'Share Tech Mono', monospace" }}>
                      ⏳ AI analysis pending... refresh in 30 seconds
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
