import { useState } from "react";
import { API, C, SEV_COLOR, timeAgo } from "../config";
import { useFetch } from "../hooks/useFetch";
import { SeverityBadge } from "../components/ui/SeverityBadge";

const LIMIT = 25;

const filterStyle = {
  background: C.surface, border: `1px solid ${C.border}`,
  borderRadius: 6, padding: "6px 12px", color: C.text,
  fontSize: 13, fontFamily: "'Share Tech Mono', monospace",
  outline: "none", cursor: "pointer",
};

export default function LiveEvents() {
  const [source, setSource]     = useState("");
  const [severity, setSeverity] = useState("");
  const [search, setSearch]     = useState("");
  const [page, setPage]         = useState(0);

  const url = `${API}/events?limit=${LIMIT}&offset=${page * LIMIT}` +
    (source   ? `&source=${source}`     : "") +
    (severity ? `&severity=${severity}` : "") +
    (search   ? `&search=${encodeURIComponent(search)}` : "");

  const { data, loading } = useFetch(url, [source, severity, search, page]);
  const events = data?.events || [];

  return (
    <div>
      {/* Filters */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
        <select style={filterStyle} value={source} onChange={e => { setSource(e.target.value); setPage(0); }}>
          <option value="">All Sources</option>
          <option value="ssh">SSH</option>
          <option value="apache">Apache</option>
          <option value="syslog">Syslog</option>
        </select>
        <select style={filterStyle} value={severity} onChange={e => { setSeverity(e.target.value); setPage(0); }}>
          <option value="">All Severities</option>
          {["CRITICAL","ERROR","WARNING","INFO","DEBUG"].map(s =>
            <option key={s} value={s}>{s}</option>)}
        </select>
        <input
          style={{ ...filterStyle, flex: 1, minWidth: 200 }}
          placeholder="🔍 Search events..."
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0); }}
        />
        <div style={{
          fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: C.muted,
          display: "flex", alignItems: "center", padding: "0 4px",
        }}>
          {loading ? "Loading..." : `${events.length} results`}
        </div>
      </div>

      {/* Table */}
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: C.surface }}>
              {["Time", "Source", "Severity", "IP", "Event Type", "Message"].map(h => (
                <th key={h} style={{
                  padding: "12px 16px", textAlign: "left",
                  color: C.muted, fontSize: 11, letterSpacing: 1.2,
                  textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace",
                  fontWeight: 500, borderBottom: `1px solid ${C.border}`,
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={{ padding: 40, textAlign: "center", color: C.muted }}>
                <span style={{ animation: "pulse 1.5s infinite", display: "inline-block" }}>⬡ Loading events…</span>
              </td></tr>
            ) : events.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: 40, textAlign: "center", color: C.muted }}>
                No events found
              </td></tr>
            ) : events.map((ev, i) => (
              <tr key={ev.id} style={{
                borderBottom: `1px solid ${C.border}`,
                background: i % 2 === 0 ? "transparent" : C.surface + "55",
                transition: "background 0.15s",
              }}
                onMouseEnter={e => e.currentTarget.style.background = C.border + "44"}
                onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? "transparent" : C.surface + "55"}
              >
                <td style={{ padding: "10px 16px", fontSize: 12, color: C.muted, fontFamily: "'Share Tech Mono', monospace", whiteSpace: "nowrap" }}>
                  {timeAgo(ev.timestamp)}
                </td>
                <td style={{ padding: "10px 16px" }}>
                  <span style={{ background: C.accent + "22", color: C.accent, border: `1px solid ${C.accent}44`, borderRadius: 4, padding: "2px 8px", fontSize: 11, fontFamily: "'Share Tech Mono', monospace" }}>
                    {ev.source_name?.toUpperCase()}
                  </span>
                </td>
                <td style={{ padding: "10px 16px" }}><SeverityBadge sev={ev.severity} /></td>
                <td style={{ padding: "10px 16px", fontSize: 12, fontFamily: "'Share Tech Mono', monospace", color: C.orange }}>
                  {ev.ip_address || "—"}
                </td>
                <td style={{ padding: "10px 16px", fontSize: 12, fontFamily: "'Share Tech Mono', monospace", color: C.purple }}>
                  {ev.event_type || "—"}
                </td>
                <td style={{ padding: "10px 16px", fontSize: 12, color: C.text, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {ev.message}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div style={{ display: "flex", justifyContent: "center", gap: 10, marginTop: 16 }}>
        {[
          { label: "← Prev", action: () => setPage(p => Math.max(0, p - 1)), disabled: page === 0 },
          { label: "Next →", action: () => setPage(p => p + 1), disabled: events.length < LIMIT },
        ].map(btn => (
          <button key={btn.label} onClick={btn.action} disabled={btn.disabled}
            style={{
              background: C.card, border: `1px solid ${C.border}`,
              color: btn.disabled ? C.muted : C.text, borderRadius: 6,
              padding: "6px 16px", cursor: btn.disabled ? "default" : "pointer",
              fontFamily: "'Share Tech Mono', monospace", fontSize: 13,
            }}>
            {btn.label}
          </button>
        ))}
        <span style={{ color: C.muted, padding: "6px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 13 }}>
          Page {page + 1}
        </span>
      </div>
    </div>
  );
}
