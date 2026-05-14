import { useState, useEffect, useCallback } from "react";
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from "recharts";

// ── Config ─────────────────────────────────────────────────────────────────
const API = "http://192.168.56.101:5000/api";
const REFRESH_MS = 10000; // auto-refresh every 10s

// ── Color palette ──────────────────────────────────────────────────────────
const C = {
  bg:       "#0a0e1a",
  surface:  "#0f1628",
  card:     "#131c35",
  border:   "#1e2d50",
  accent:   "#00d4ff",
  green:    "#00e676",
  yellow:   "#ffd600",
  orange:   "#ff6d00",
  red:      "#ff1744",
  purple:   "#7c4dff",
  text:     "#e8f0fe",
  muted:    "#5c7099",
};

const SEV_COLOR = {
  CRITICAL: C.red,
  HIGH:     C.orange,
  MEDIUM:   C.yellow,
  LOW:      C.green,
  INFO:     C.accent,
  WARNING:  C.yellow,
  ERROR:    C.orange,
  DEBUG:    C.muted,
};

// ── Helpers ────────────────────────────────────────────────────────────────
function timeAgo(iso) {
  const diff = Date.now() - new Date(iso);
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function useFetch(url, deps = []) {
  const [data, setData]     = useState(null);
  const [loading, setLoad]  = useState(true);
  const [error, setError]   = useState(null);

  const load = useCallback(async () => {
    try {
      setLoad(true);
      const r = await fetch(url);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setData(await r.json());
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoad(false);
    }
  }, [url]);

  useEffect(() => { load(); }, [load, ...deps]);
  useEffect(() => {
    const t = setInterval(load, REFRESH_MS);
    return () => clearInterval(t);
  }, [load]);

  return { data, loading, error, reload: load };
}

// ── Sub-components ─────────────────────────────────────────────────────────

function ScanLine() {
  return (
    <div style={{
      position: "fixed", top: 0, left: 0, right: 0, height: "2px",
      background: `linear-gradient(90deg, transparent, ${C.accent}, transparent)`,
      animation: "scanline 3s linear infinite", zIndex: 9999, opacity: 0.6,
    }} />
  );
}

function StatCard({ label, value, sub, color = C.accent, icon }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${C.border}`,
      borderRadius: 12, padding: "20px 24px",
      borderTop: `3px solid ${color}`, position: "relative", overflow: "hidden",
    }}>
      <div style={{
        position: "absolute", top: 12, right: 16,
        fontSize: 28, opacity: 0.15,
      }}>{icon}</div>
      <div style={{ fontSize: 12, color: C.muted, textTransform: "uppercase",
        letterSpacing: 1.5, fontFamily: "'Share Tech Mono', monospace" }}>
        {label}
      </div>
      <div style={{
        fontSize: 38, fontWeight: 700, color, fontFamily: "'Share Tech Mono', monospace",
        lineHeight: 1.2, marginTop: 6,
      }}>{value ?? "—"}</div>
      {sub && <div style={{ fontSize: 11, color: C.muted, marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function SeverityBadge({ sev }) {
  const color = SEV_COLOR[sev] || C.muted;
  return (
    <span style={{
      background: color + "22", color, border: `1px solid ${color}55`,
      borderRadius: 4, padding: "2px 8px", fontSize: 11,
      fontFamily: "'Share Tech Mono', monospace", fontWeight: 600,
      letterSpacing: 1,
    }}>{sev}</span>
  );
}

function AiBanner({ status }) {
  if (!status?.banner) return null;
  const { type, message } = status.banner;
  const colors = {
    success: { bg: "#00e67611", border: C.green,  text: C.green  },
    warning: { bg: "#ffd60011", border: C.yellow, text: C.yellow },
    error:   { bg: "#ff174411", border: C.red,    text: C.red    },
    info:    { bg: "#00d4ff11", border: C.accent, text: C.accent },
  };
  const s = colors[type] || colors.info;
  return (
    <div style={{
      background: s.bg, border: `1px solid ${s.border}`,
      borderRadius: 8, padding: "10px 16px", marginBottom: 20,
      color: s.text, fontSize: 13,
      fontFamily: "'Share Tech Mono', monospace",
      display: "flex", alignItems: "center", gap: 10,
    }}>
      <span style={{ fontSize: 16 }}>
        {type === "success" ? "✅" : type === "warning" ? "⚠️" : type === "error" ? "❌" : "ℹ️"}
      </span>
      <span>{message}</span>
    </div>
  );
}

// ── Page: Overview ─────────────────────────────────────────────────────────

function Overview() {
  const { data: stats }     = useFetch(`${API}/stats`);
  const { data: aiStatus }  = useFetch(`${API}/ai-status`);

  const timeline = (stats?.timeline || []).map(t => ({
    hour: new Date(t.hour).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    events: t.count,
  }));

  const srcData = Object.entries(stats?.events_by_source || {}).map(([name, value]) => ({
    name: name.toUpperCase(), value,
  }));

  const sevData = Object.entries(stats?.alerts_by_severity || {}).map(([name, value]) => ({
    name, value, fill: SEV_COLOR[name] || C.muted,
  }));

  const PIE_COLORS = [C.accent, C.purple, C.green, C.yellow];

  return (
    <div>
      <AiBanner status={aiStatus} />

      {/* Stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
        <StatCard label="Events (24h)"    value={stats?.events_24h}      color={C.accent}  icon="📡" />
        <StatCard label="Active Alerts"   value={stats?.active_alerts}   color={C.red}     icon="🚨" />
        <StatCard label="Critical Alerts" value={stats?.alerts_by_severity?.CRITICAL ?? 0} color={C.red} icon="💀" />
        <StatCard label="Top Attacker"    value={stats?.top_attacking_ips?.[0]?.ip ?? "None"}
          sub={`${stats?.top_attacking_ips?.[0]?.count ?? 0} events`} color={C.orange} icon="🎯" />
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, marginBottom: 24 }}>
        {/* Timeline */}
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
          <div style={{ color: C.muted, fontSize: 11, letterSpacing: 1.5,
            textTransform: "uppercase", marginBottom: 16, fontFamily: "'Share Tech Mono', monospace" }}>
            Events Timeline (24h)
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="hour" stroke={C.muted} tick={{ fontSize: 10 }} />
              <YAxis stroke={C.muted} tick={{ fontSize: 10 }} />
              <Tooltip contentStyle={{ background: C.surface, border: `1px solid ${C.border}`,
                borderRadius: 8, color: C.text }} />
              <Line type="monotone" dataKey="events" stroke={C.accent}
                strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Source pie */}
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
          <div style={{ color: C.muted, fontSize: 11, letterSpacing: 1.5,
            textTransform: "uppercase", marginBottom: 16, fontFamily: "'Share Tech Mono', monospace" }}>
            Events by Source
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={srcData} dataKey="value" nameKey="name"
                cx="50%" cy="50%" outerRadius={75} label={({ name, percent }) =>
                  `${name} ${(percent * 100).toFixed(0)}%`}
                labelLine={false}>
                {srcData.map((_, i) => (
                  <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: C.surface, border: `1px solid ${C.border}`,
                borderRadius: 8, color: C.text }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Bottom row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Alert severity bar */}
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
          <div style={{ color: C.muted, fontSize: 11, letterSpacing: 1.5,
            textTransform: "uppercase", marginBottom: 16, fontFamily: "'Share Tech Mono', monospace" }}>
            Alerts by Severity
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={sevData}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="name" stroke={C.muted} tick={{ fontSize: 10 }} />
              <YAxis stroke={C.muted} tick={{ fontSize: 10 }} />
              <Tooltip contentStyle={{ background: C.surface, border: `1px solid ${C.border}`,
                borderRadius: 8, color: C.text }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {sevData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top attacking IPs */}
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
          <div style={{ color: C.muted, fontSize: 11, letterSpacing: 1.5,
            textTransform: "uppercase", marginBottom: 16, fontFamily: "'Share Tech Mono', monospace" }}>
            Top Attacking IPs
          </div>
          {(stats?.top_attacking_ips || []).map((ip, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center",
              gap: 12, marginBottom: 10 }}>
              <span style={{ color: C.red, fontFamily: "'Share Tech Mono', monospace",
                fontSize: 13, minWidth: 130 }}>{ip.ip}</span>
              <div style={{ flex: 1, background: C.border, borderRadius: 4, height: 6 }}>
                <div style={{
                  width: `${(ip.count / (stats.top_attacking_ips[0]?.count || 1)) * 100}%`,
                  background: `linear-gradient(90deg, ${C.red}, ${C.orange})`,
                  height: "100%", borderRadius: 4,
                  transition: "width 0.5s ease",
                }} />
              </div>
              <span style={{ color: C.muted, fontSize: 12,
                fontFamily: "'Share Tech Mono', monospace" }}>{ip.count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Page: Live Events ──────────────────────────────────────────────────────

function LiveEvents() {
  const [source, setSource]     = useState("");
  const [severity, setSeverity] = useState("");
  const [search, setSearch]     = useState("");
  const [page, setPage]         = useState(0);
  const LIMIT = 25;

  const url = `${API}/events?limit=${LIMIT}&offset=${page * LIMIT}` +
    (source   ? `&source=${source}`     : "") +
    (severity ? `&severity=${severity}` : "") +
    (search   ? `&search=${encodeURIComponent(search)}` : "");

  const { data, loading } = useFetch(url, [source, severity, search, page]);
  const events = data?.events || [];

  const filterStyle = {
    background: C.surface, border: `1px solid ${C.border}`,
    borderRadius: 6, padding: "6px 12px", color: C.text,
    fontSize: 13, fontFamily: "'Share Tech Mono', monospace",
    outline: "none", cursor: "pointer",
  };

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
          placeholder="Search events..."
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0); }}
        />
      </div>

      {/* Table */}
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: C.surface }}>
              {["Time", "Source", "Severity", "IP", "Event Type", "Message"].map(h => (
                <th key={h} style={{ padding: "12px 16px", textAlign: "left",
                  color: C.muted, fontSize: 11, letterSpacing: 1.2,
                  textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace",
                  fontWeight: 500, borderBottom: `1px solid ${C.border}` }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={{ padding: 40, textAlign: "center", color: C.muted }}>
                Loading...
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
                <td style={{ padding: "10px 16px", fontSize: 12, color: C.muted,
                  fontFamily: "'Share Tech Mono', monospace", whiteSpace: "nowrap" }}>
                  {timeAgo(ev.timestamp)}
                </td>
                <td style={{ padding: "10px 16px" }}>
                  <span style={{ background: C.accent + "22", color: C.accent,
                    border: `1px solid ${C.accent}44`, borderRadius: 4,
                    padding: "2px 8px", fontSize: 11,
                    fontFamily: "'Share Tech Mono', monospace" }}>
                    {ev.source_name?.toUpperCase()}
                  </span>
                </td>
                <td style={{ padding: "10px 16px" }}><SeverityBadge sev={ev.severity} /></td>
                <td style={{ padding: "10px 16px", fontSize: 12,
                  fontFamily: "'Share Tech Mono', monospace", color: C.orange }}>
                  {ev.ip_address || "—"}
                </td>
                <td style={{ padding: "10px 16px", fontSize: 12,
                  fontFamily: "'Share Tech Mono', monospace", color: C.purple }}>
                  {ev.event_type || "—"}
                </td>
                <td style={{ padding: "10px 16px", fontSize: 12,
                  color: C.text, maxWidth: 300, overflow: "hidden",
                  textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {ev.message}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div style={{ display: "flex", justifyContent: "center", gap: 10, marginTop: 16 }}>
        <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
          style={{ background: C.card, border: `1px solid ${C.border}`,
            color: page === 0 ? C.muted : C.text, borderRadius: 6,
            padding: "6px 16px", cursor: page === 0 ? "default" : "pointer",
            fontFamily: "'Share Tech Mono', monospace", fontSize: 13 }}>
          ← Prev
        </button>
        <span style={{ color: C.muted, padding: "6px 12px",
          fontFamily: "'Share Tech Mono', monospace", fontSize: 13 }}>
          Page {page + 1}
        </span>
        <button onClick={() => setPage(p => p + 1)} disabled={events.length < LIMIT}
          style={{ background: C.card, border: `1px solid ${C.border}`,
            color: events.length < LIMIT ? C.muted : C.text, borderRadius: 6,
            padding: "6px 16px", cursor: events.length < LIMIT ? "default" : "pointer",
            fontFamily: "'Share Tech Mono', monospace", fontSize: 13 }}>
          Next →
        </button>
      </div>
    </div>
  );
}

// ── Page: Alerts ───────────────────────────────────────────────────────────

function Alerts() {
  const [expanded, setExpanded]     = useState(null);
  const [resolving, setResolving]   = useState(null);
  const [showResolved, setShowResolved] = useState(false);
  const [sevFilter, setSevFilter]   = useState("");

  const url = `${API}/alerts?resolved=${showResolved}` +
    (sevFilter ? `&severity=${sevFilter}` : "");
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

  const filterStyle = {
    background: C.surface, border: `1px solid ${C.border}`,
    borderRadius: 6, padding: "6px 12px", color: C.text,
    fontSize: 13, fontFamily: "'Share Tech Mono', monospace", outline: "none",
  };

  return (
    <div>
      {/* Controls */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16, alignItems: "center" }}>
        <select style={filterStyle} value={sevFilter}
          onChange={e => setSevFilter(e.target.value)}>
          <option value="">All Severities</option>
          {["CRITICAL","HIGH","MEDIUM","LOW"].map(s =>
            <option key={s} value={s}>{s}</option>)}
        </select>
        <button onClick={() => setShowResolved(r => !r)}
          style={{ background: showResolved ? C.green + "22" : C.surface,
            border: `1px solid ${showResolved ? C.green : C.border}`,
            color: showResolved ? C.green : C.muted,
            borderRadius: 6, padding: "6px 14px", cursor: "pointer",
            fontFamily: "'Share Tech Mono', monospace", fontSize: 13 }}>
          {showResolved ? "✅ Showing Resolved" : "Show Resolved"}
        </button>
        <span style={{ color: C.muted, fontSize: 12,
          fontFamily: "'Share Tech Mono', monospace", marginLeft: "auto" }}>
          {alerts.length} alert{alerts.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Alert cards */}
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {alerts.length === 0 ? (
          <div style={{ textAlign: "center", padding: 60, color: C.muted,
            fontFamily: "'Share Tech Mono', monospace" }}>
            {showResolved ? "No resolved alerts" : "✅ No active alerts"}
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
            }}>
              {/* Header row */}
              <div style={{ display: "flex", alignItems: "center",
                gap: 12, padding: "14px 18px", cursor: "pointer" }}
                onClick={() => setExpanded(isOpen ? null : alert.id)}>
                <SeverityBadge sev={alert.severity} />
                <div style={{ flex: 1 }}>
                  <div style={{ color: C.text, fontSize: 14, fontWeight: 500 }}>
                    {alert.title}
                  </div>
                  <div style={{ color: C.muted, fontSize: 12, marginTop: 2,
                    fontFamily: "'Share Tech Mono', monospace" }}>
                    {alert.rule_name} · {alert.event_count} event{alert.event_count !== 1 ? "s" : ""}
                    · {timeAgo(alert.created_at)}
                    {(alert.related_ips || []).length > 0 &&
                      ` · IP: ${alert.related_ips.join(", ")}`}
                  </div>
                </div>
                <span style={{ color: C.muted, fontSize: 18 }}>{isOpen ? "▲" : "▼"}</span>
                {!alert.is_resolved && (
                  <button
                    onClick={e => { e.stopPropagation(); resolveAlert(alert.id); }}
                    disabled={resolving === alert.id}
                    style={{ background: C.green + "22", border: `1px solid ${C.green}55`,
                      color: C.green, borderRadius: 6, padding: "4px 12px",
                      cursor: "pointer", fontSize: 12,
                      fontFamily: "'Share Tech Mono', monospace" }}>
                    {resolving === alert.id ? "..." : "Resolve"}
                  </button>
                )}
              </div>

              {/* Expanded: AI explanation */}
              {isOpen && (
                <div style={{ borderTop: `1px solid ${C.border}`,
                  padding: "16px 18px", background: C.surface + "88" }}>
                  {alert.ai_explanation ? (
                    <pre style={{ fontFamily: "'Share Tech Mono', monospace",
                      fontSize: 13, color: C.text, whiteSpace: "pre-wrap",
                      lineHeight: 1.8, margin: 0 }}>
                      {alert.ai_explanation}
                    </pre>
                  ) : (
                    <div style={{ color: C.muted, fontSize: 13,
                      fontFamily: "'Share Tech Mono', monospace" }}>
                      ⏳ AI analysis pending...
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

// ── Page: Reports ──────────────────────────────────────────────────────────

function Reports() {
  const { data: stats }  = useFetch(`${API}/stats`);
  const { data: alerts } = useFetch(`${API}/alerts?limit=200`);
  const now = new Date().toLocaleString();

  const totalAlerts   = alerts?.count || 0;
  const criticalCount = stats?.alerts_by_severity?.CRITICAL || 0;
  const topIp         = stats?.top_attacking_ips?.[0];

  const rows = [
    ["Report Generated",    now],
    ["Total Events (24h)",  stats?.events_24h ?? "—"],
    ["Active Alerts",       stats?.active_alerts ?? "—"],
    ["Critical Alerts",     criticalCount],
    ["Top Attacking IP",    topIp ? `${topIp.ip} (${topIp.count} events)` : "None"],
    ["SSH Events",          stats?.events_by_source?.ssh ?? 0],
    ["Apache Events",       stats?.events_by_source?.apache ?? 0],
    ["Syslog Events",       stats?.events_by_source?.syslog ?? 0],
  ];

  return (
    <div>
      <div style={{ background: C.card, border: `1px solid ${C.border}`,
        borderRadius: 12, padding: 24, marginBottom: 20 }}>
        <div style={{ color: C.accent, fontSize: 11, letterSpacing: 2,
          textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace",
          marginBottom: 8 }}>Security Report Summary</div>
        <div style={{ color: C.muted, fontSize: 12,
          fontFamily: "'Share Tech Mono', monospace" }}>
          Auto-generated · Refreshes every 10 seconds
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        {rows.map(([label, value]) => (
          <div key={label} style={{ background: C.card, border: `1px solid ${C.border}`,
            borderRadius: 8, padding: "14px 18px",
            display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ color: C.muted, fontSize: 13 }}>{label}</span>
            <span style={{ color: C.text, fontSize: 13,
              fontFamily: "'Share Tech Mono', monospace", fontWeight: 600 }}>{value}</span>
          </div>
        ))}
      </div>

      {/* Recent critical alerts */}
      <div style={{ background: C.card, border: `1px solid ${C.border}`,
        borderRadius: 12, padding: 24, marginTop: 20 }}>
        <div style={{ color: C.red, fontSize: 11, letterSpacing: 2,
          textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace",
          marginBottom: 16 }}>Recent Critical & High Alerts</div>
        {(alerts?.alerts || [])
          .filter(a => ["CRITICAL","HIGH"].includes(a.severity))
          .slice(0, 8)
          .map(a => (
            <div key={a.id} style={{ display: "flex", gap: 12,
              padding: "8px 0", borderBottom: `1px solid ${C.border}`,
              alignItems: "center" }}>
              <SeverityBadge sev={a.severity} />
              <span style={{ flex: 1, fontSize: 13, color: C.text }}>{a.title}</span>
              <span style={{ fontSize: 11, color: C.muted,
                fontFamily: "'Share Tech Mono', monospace" }}>
                {timeAgo(a.created_at)}
              </span>
            </div>
          ))}
      </div>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────

const PAGES = [
  { id: "overview",  label: "Overview",    icon: "⬡" },
  { id: "events",    label: "Live Events", icon: "◈" },
  { id: "alerts",    label: "Alerts",      icon: "◉" },
  { id: "reports",   label: "Reports",     icon: "◫" },
];

export default function App() {
  const [page, setPage] = useState("overview");
  const { data: stats } = useFetch(`${API}/stats`);

  const critCount = stats?.alerts_by_severity?.CRITICAL || 0;

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text,
      fontFamily: "'Syne', sans-serif" }}>
      <ScanLine />

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        @keyframes scanline {
          0%   { transform: translateX(-100%); }
          100% { transform: translateX(100vw); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.4; }
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(10px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        select option { background: ${C.surface}; }
      `}</style>

      {/* Sidebar */}
      <div style={{
        position: "fixed", left: 0, top: 0, bottom: 0, width: 220,
        background: C.surface, borderRight: `1px solid ${C.border}`,
        display: "flex", flexDirection: "column", zIndex: 100,
      }}>
        {/* Logo */}
        <div style={{ padding: "24px 20px", borderBottom: `1px solid ${C.border}` }}>
          <div style={{ fontSize: 11, color: C.muted, letterSpacing: 3,
            textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace" }}>
            ◈ SIEM
          </div>
          <div style={{ fontSize: 20, fontWeight: 700, color: C.accent,
            letterSpacing: 1, marginTop: 4 }}>
            SecureWatch
          </div>
          <div style={{ fontSize: 10, color: C.muted, marginTop: 2,
            fontFamily: "'Share Tech Mono', monospace" }}>
            v1.0 · ACTIVE
            <span style={{ display: "inline-block", width: 6, height: 6,
              background: C.green, borderRadius: "50%", marginLeft: 6,
              animation: "pulse 2s infinite" }} />
          </div>
        </div>

        {/* Nav */}
        <nav style={{ padding: "16px 12px", flex: 1 }}>
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
                }}>
                <span style={{ fontSize: 16 }}>{p.icon}</span>
                {p.label}
                {p.id === "alerts" && critCount > 0 && (
                  <span style={{ marginLeft: "auto", background: C.red,
                    color: "#fff", borderRadius: 10, padding: "1px 7px",
                    fontSize: 10, fontFamily: "'Share Tech Mono', monospace" }}>
                    {critCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Footer */}
        <div style={{ padding: "16px 20px", borderTop: `1px solid ${C.border}` }}>
          <div style={{ fontSize: 10, color: C.muted,
            fontFamily: "'Share Tech Mono', monospace", lineHeight: 1.8 }}>
            <div>Kali Linux · localhost</div>
            <div style={{ color: C.green }}>● All agents running</div>
            <div style={{ marginTop: 4 }}>
              Auto-refresh: {REFRESH_MS / 1000}s
            </div>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div style={{ marginLeft: 220, padding: "28px 32px",
        animation: "fadeIn 0.3s ease" }}>
        {/* Page header */}
        <div style={{ marginBottom: 24, display: "flex",
          justifyContent: "space-between", alignItems: "flex-end" }}>
          <div>
            <div style={{ fontSize: 11, color: C.muted, letterSpacing: 2,
              textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace" }}>
              SIEM · SecureWatch
            </div>
            <h1 style={{ fontSize: 26, fontWeight: 700, color: C.text,
              marginTop: 4, letterSpacing: -0.5 }}>
              {PAGES.find(p => p.id === page)?.label}
            </h1>
          </div>
          <div style={{ fontSize: 11, color: C.muted,
            fontFamily: "'Share Tech Mono', monospace", textAlign: "right" }}>
            <div>{new Date().toLocaleDateString()}</div>
            <div style={{ color: C.accent }}>{new Date().toLocaleTimeString()}</div>
          </div>
        </div>

        {/* Page content */}
        {page === "overview" && <Overview />}
        {page === "events"   && <LiveEvents />}
        {page === "alerts"   && <Alerts />}
        {page === "reports"  && <Reports />}
      </div>
    </div>
  );
}
