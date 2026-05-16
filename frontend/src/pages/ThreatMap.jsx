import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell,
} from "recharts";
import { API, C, SEV_COLOR } from "../config";
import { useFetch } from "../hooks/useFetch";

function ThreatRing({ count, max, color }) {
  const pct = max > 0 ? (count / max) * 100 : 0;
  const r = 30, cx = 38, cy = 38, stroke = 6;
  const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;
  return (
    <svg width={76} height={76}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.border} strokeWidth={stroke} />
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={stroke}
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`}
        style={{ transition: "stroke-dasharray 1s ease" }}
      />
      <text x={cx} y={cy + 4} textAnchor="middle" fill={color} fontSize="11" fontFamily="'Share Tech Mono', monospace">
        {count}
      </text>
    </svg>
  );
}

const SEV_KEYS = ["CRITICAL","HIGH","MEDIUM","LOW","INFO","WARNING"];

export default function ThreatMap() {
  const { data: stats }  = useFetch(`${API}/stats`);
  const { data: alerts } = useFetch(`${API}/alerts?limit=200`);

  const topIPs = stats?.top_attacking_ips || [];
  const maxCount = topIPs[0]?.count || 1;

  // Build per-IP alert breakdown from alerts data
  const ipAlertMap = {};
  (alerts?.alerts || []).forEach(a => {
    (a.related_ips || []).forEach(ip => {
      if (!ipAlertMap[ip]) ipAlertMap[ip] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      const sev = a.severity || "LOW";
      if (ipAlertMap[ip][sev] !== undefined) ipAlertMap[ip][sev]++;
    });
  });

  // Severity distribution bar chart
  const sevData = Object.entries(stats?.alerts_by_severity || {}).map(([name, value]) => ({
    name, value, fill: SEV_COLOR[name] || C.muted,
  }));

  // Attack source breakdown
  const sourceData = Object.entries(stats?.events_by_source || {}).map(([name, value]) => ({
    name: name.toUpperCase(), value,
  }));

  const cardStyle = {
    background: C.card, border: `1px solid ${C.border}`,
    borderRadius: 12, padding: "20px 24px",
  };

  return (
    <div>
      {/* Summary strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 16, marginBottom: 24 }}>
        {[
          { label: "Unique Attackers", value: topIPs.length, color: C.red, icon: "🎯" },
          { label: "Total Attack Events", value: topIPs.reduce((s, ip) => s + ip.count, 0), color: C.orange, icon: "⚡" },
          { label: "Critical Alerts", value: stats?.alerts_by_severity?.CRITICAL ?? 0, color: C.red, icon: "💀" },
        ].map(({ label, value, color, icon }) => (
          <div key={label} style={{
            ...cardStyle, borderTop: `3px solid ${color}`,
            display: "flex", alignItems: "center", gap: 16,
          }}>
            <span style={{ fontSize: 32 }}>{icon}</span>
            <div>
              <div style={{ fontSize: 11, color: C.muted, textTransform: "uppercase", letterSpacing: 1.5, fontFamily: "'Share Tech Mono', monospace" }}>{label}</div>
              <div style={{ fontSize: 34, fontWeight: 700, color, fontFamily: "'Share Tech Mono', monospace" }}>{value ?? "—"}</div>
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 16, marginBottom: 16 }}>
        {/* IP Attack Ranking */}
        <div style={cardStyle}>
          <div style={{ color: C.muted, fontSize: 11, letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 20, fontFamily: "'Share Tech Mono', monospace" }}>
            🎯 Top Attacking IPs — Ranked Threat Board
          </div>
          {topIPs.length === 0 ? (
            <div style={{ color: C.muted, textAlign: "center", padding: "40px 0", fontFamily: "'Share Tech Mono', monospace", fontSize: 13 }}>
              ✅ No attackers detected in the last 24 hours
            </div>
          ) : topIPs.map((ip, i) => {
            const alertBreakdown = ipAlertMap[ip.ip] || {};
            const threatLevel = alertBreakdown.CRITICAL > 0 ? "CRITICAL"
              : alertBreakdown.HIGH > 0 ? "HIGH"
              : alertBreakdown.MEDIUM > 0 ? "MEDIUM" : "LOW";
            const color = SEV_COLOR[threatLevel] || C.muted;
            return (
              <div key={ip.ip} style={{
                display: "flex", alignItems: "center", gap: 16,
                padding: "14px 0", borderBottom: `1px solid ${C.border}`,
              }}>
                {/* Rank */}
                <div style={{
                  width: 28, height: 28, borderRadius: "50%",
                  background: i === 0 ? C.red + "33" : i === 1 ? C.orange + "33" : C.border,
                  border: `1px solid ${i === 0 ? C.red : i === 1 ? C.orange : C.border}`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 11, fontWeight: 700, color: i < 2 ? (i === 0 ? C.red : C.orange) : C.muted,
                  fontFamily: "'Share Tech Mono', monospace", flexShrink: 0,
                }}>#{i + 1}</div>

                {/* Ring */}
                <ThreatRing count={ip.count} max={maxCount} color={color} />

                {/* IP & bar */}
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <span style={{ color, fontFamily: "'Share Tech Mono', monospace", fontSize: 14, fontWeight: 600 }}>
                      {ip.ip}
                    </span>
                    <span style={{ color: C.muted, fontSize: 11, fontFamily: "'Share Tech Mono', monospace" }}>
                      {ip.count} events
                    </span>
                  </div>
                  {/* Attack bar */}
                  <div style={{ background: C.border, borderRadius: 4, height: 8, position: "relative", overflow: "hidden" }}>
                    <div style={{
                      width: `${(ip.count / maxCount) * 100}%`,
                      background: `linear-gradient(90deg, ${color}, ${color}88)`,
                      height: "100%", borderRadius: 4,
                      transition: "width 1s cubic-bezier(0.4,0,0.2,1)",
                      boxShadow: `0 0 8px ${color}66`,
                    }} />
                  </div>
                  {/* Alert type pills */}
                  <div style={{ display: "flex", gap: 6, marginTop: 6, flexWrap: "wrap" }}>
                    {Object.entries(alertBreakdown).filter(([, v]) => v > 0).map(([sev, cnt]) => (
                      <span key={sev} style={{
                        background: (SEV_COLOR[sev] || C.muted) + "22",
                        color: SEV_COLOR[sev] || C.muted,
                        border: `1px solid ${(SEV_COLOR[sev] || C.muted)}44`,
                        borderRadius: 3, padding: "1px 6px", fontSize: 10,
                        fontFamily: "'Share Tech Mono', monospace",
                      }}>
                        {sev} ×{cnt}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Charts column */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div style={cardStyle}>
            <div style={{ color: C.muted, fontSize: 11, letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 16, fontFamily: "'Share Tech Mono', monospace" }}>
              Alert Severity Distribution
            </div>
            <ResponsiveContainer width="100%" height={150}>
              <BarChart data={sevData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke={C.border} horizontal={false} />
                <XAxis type="number" stroke={C.muted} tick={{ fontSize: 10 }} />
                <YAxis type="category" dataKey="name" stroke={C.muted} tick={{ fontSize: 10 }} width={65} />
                <Tooltip contentStyle={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {sevData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div style={cardStyle}>
            <div style={{ color: C.muted, fontSize: 11, letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 16, fontFamily: "'Share Tech Mono', monospace" }}>
              Attack Vectors
            </div>
            {sourceData.map(({ name, value }, i) => {
              const colors = [C.accent, C.purple, C.green];
              const c = colors[i % colors.length];
              const pct = sourceData.reduce((s, d) => s + d.value, 0);
              return (
                <div key={name} style={{ marginBottom: 14 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <span style={{ color: C.text, fontSize: 12, fontFamily: "'Share Tech Mono', monospace" }}>{name}</span>
                    <span style={{ color: C.muted, fontSize: 11, fontFamily: "'Share Tech Mono', monospace" }}>
                      {value} ({pct > 0 ? ((value / pct) * 100).toFixed(1) : 0}%)
                    </span>
                  </div>
                  <div style={{ background: C.border, borderRadius: 4, height: 6 }}>
                    <div style={{
                      width: `${pct > 0 ? (value / pct) * 100 : 0}%`,
                      background: `linear-gradient(90deg, ${c}, ${c}88)`,
                      height: "100%", borderRadius: 4,
                      transition: "width 1s ease", boxShadow: `0 0 6px ${c}55`,
                    }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
