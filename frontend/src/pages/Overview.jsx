import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import { API, C, SEV_COLOR } from "../config";
import { useFetch } from "../hooks/useFetch";
import { StatCard } from "../components/ui/StatCard";
import { AiBanner } from "../components/ui/AiBanner";

const PIE_COLORS = [C.accent, C.purple, C.green, C.yellow, C.orange];

export default function Overview() {
  const { data: stats }    = useFetch(`${API}/stats`);
  const { data: aiStatus } = useFetch(`${API}/ai-status`);

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

  const cardStyle = { background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 };
  const labelStyle = {
    color: C.muted, fontSize: 11, letterSpacing: 1.5,
    textTransform: "uppercase", marginBottom: 16,
    fontFamily: "'Share Tech Mono', monospace",
  };

  return (
    <div>
      <AiBanner status={aiStatus} />

      {/* Stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
        <StatCard label="Events (24h)"    value={stats?.events_24h}      color={C.accent}  icon="📡" />
        <StatCard label="Active Alerts"   value={stats?.active_alerts}   color={C.red}     icon="🚨" />
        <StatCard label="Critical Alerts" value={stats?.alerts_by_severity?.CRITICAL ?? 0} color={C.red} icon="💀" />
        <StatCard
          label="Top Attacker"
          value={stats?.top_attacking_ips?.[0]?.ip ?? "None"}
          sub={`${stats?.top_attacking_ips?.[0]?.count ?? 0} events`}
          color={C.orange} icon="🎯"
        />
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, marginBottom: 24 }}>
        <div style={cardStyle}>
          <div style={labelStyle}>Events Timeline (24h)</div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="hour" stroke={C.muted} tick={{ fontSize: 10 }} />
              <YAxis stroke={C.muted} tick={{ fontSize: 10 }} />
              <Tooltip contentStyle={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
              <Line type="monotone" dataKey="events" stroke={C.accent} strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div style={cardStyle}>
          <div style={labelStyle}>Events by Source</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={srcData} dataKey="value" nameKey="name"
                cx="50%" cy="50%" outerRadius={72} innerRadius={30}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                labelLine={false}
              >
                {srcData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Bottom row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div style={cardStyle}>
          <div style={labelStyle}>Alerts by Severity</div>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={sevData}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="name" stroke={C.muted} tick={{ fontSize: 10 }} />
              <YAxis stroke={C.muted} tick={{ fontSize: 10 }} />
              <Tooltip contentStyle={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {sevData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div style={cardStyle}>
          <div style={labelStyle}>Top Attacking IPs</div>
          {(stats?.top_attacking_ips || []).map((ip, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
              <span style={{ color: C.red, fontFamily: "'Share Tech Mono', monospace", fontSize: 13, minWidth: 130 }}>
                {ip.ip}
              </span>
              <div style={{ flex: 1, background: C.border, borderRadius: 4, height: 6 }}>
                <div style={{
                  width: `${(ip.count / (stats.top_attacking_ips[0]?.count || 1)) * 100}%`,
                  background: `linear-gradient(90deg, ${C.red}, ${C.orange})`,
                  height: "100%", borderRadius: 4, transition: "width 0.5s ease",
                }} />
              </div>
              <span style={{ color: C.muted, fontSize: 12, fontFamily: "'Share Tech Mono', monospace" }}>{ip.count}</span>
            </div>
          ))}
          {!(stats?.top_attacking_ips?.length) && (
            <div style={{ color: C.muted, fontSize: 13, fontFamily: "'Share Tech Mono', monospace", padding: "20px 0" }}>
              ✅ No attacking IPs in last 24h
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
