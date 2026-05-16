import { API, C, REFRESH_MS } from "../config";
import { useFetch } from "../hooks/useFetch";

function StatusBadge({ ok, labels = ["Online", "Offline"] }) {
  return (
    <span style={{
      background: ok ? C.green + "22" : C.red + "22",
      color: ok ? C.green : C.red,
      border: `1px solid ${ok ? C.green : C.red}55`,
      borderRadius: 4, padding: "2px 10px", fontSize: 11,
      fontFamily: "'Share Tech Mono', monospace", fontWeight: 600,
    }}>
      {ok ? `✓ ${labels[0]}` : `✗ ${labels[1]}`}
    </span>
  );
}

function SettingsSection({ title, children }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${C.border}`,
      borderRadius: 12, marginBottom: 16, overflow: "hidden",
    }}>
      <div style={{
        padding: "14px 20px", borderBottom: `1px solid ${C.border}`,
        background: C.surface, fontFamily: "'Share Tech Mono', monospace",
        fontSize: 11, letterSpacing: 2, textTransform: "uppercase", color: C.muted,
      }}>
        {title}
      </div>
      <div style={{ padding: "0 20px" }}>
        {children}
      </div>
    </div>
  );
}

function SettingsRow({ label, value, status, mono = false }) {
  return (
    <div style={{
      display: "flex", justifyContent: "space-between", alignItems: "center",
      padding: "14px 0", borderBottom: `1px solid ${C.border + "80"}`,
    }}>
      <span style={{ color: C.muted, fontSize: 13 }}>{label}</span>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        {value !== undefined && (
          <span style={{
            color: C.text, fontSize: 13,
            fontFamily: mono ? "'Share Tech Mono', monospace" : "inherit",
          }}>
            {value}
          </span>
        )}
        {status !== undefined && <StatusBadge ok={status} />}
      </div>
    </div>
  );
}

const AGENTS = [
  { id: "ssh",    label: "SSH Agent",    desc: "/var/log/auth.log",           icon: "🔐" },
  { id: "apache", label: "Apache Agent", desc: "/var/log/apache2/access.log", icon: "🌐" },
  { id: "syslog", label: "Syslog Agent", desc: "/var/log/syslog",             icon: "📋" },
];

const AI_PROVIDERS = [
  { key: "gemini",    label: "Google Gemini 2.0 Flash", icon: "✨" },
  { key: "anthropic", label: "Anthropic Claude",        icon: "🤖" },
  { key: "system",    label: "Rule-Based Fallback",     icon: "📋" },
];

export default function Settings() {
  const { data: health, loading: hLoad } = useFetch(`${API}/health`, [], true);
  const { data: aiStatus }               = useFetch(`${API}/ai-status`, [], true);

  const dbOk = health?.db === "connected";
  const aiHistory = aiStatus?.history || [];

  // Build provider status map
  const providerMap = {};
  aiHistory.forEach(row => {
    if (!providerMap[row.provider]) providerMap[row.provider] = row;
  });

  // Source event counts from stats
  const { data: stats } = useFetch(`${API}/stats`, [], true);
  const srcCounts = stats?.events_by_source || {};

  return (
    <div>
      {/* System Status */}
      <SettingsSection title="🖥️  System Status">
        <SettingsRow label="Dashboard Version" value="SecureWatch v2.0" mono />
        <SettingsRow label="Auto-Refresh Interval" value={`${REFRESH_MS / 1000} seconds`} mono />
        <SettingsRow label="API Endpoint" value={API} mono />
        <SettingsRow label="PostgreSQL Database" status={dbOk} />
        <SettingsRow label="API Server" status={!hLoad && health?.status === "ok"} />
      </SettingsSection>

      {/* AI Analyzer Status */}
      <SettingsSection title="🤖  AI Analyzer">
        {aiStatus?.banner && (
          <div style={{
            margin: "14px 0",
            background: C.surface, border: `1px solid ${C.border}`,
            borderRadius: 8, padding: "10px 14px",
            fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: C.muted,
          }}>
            {aiStatus.banner.message}
          </div>
        )}
        {AI_PROVIDERS.map(({ key, label, icon }) => {
          const row = providerMap[key];
          const isActive = row?.status === "active";
          const isFallback = row?.status === "fallback";
          const statusColor = isActive ? C.green : isFallback ? C.yellow : C.muted;
          return (
            <div key={key} style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "14px 0", borderBottom: `1px solid ${C.border + "80"}`,
            }}>
              <div>
                <span style={{ fontSize: 13, color: C.text }}>{icon} {label}</span>
                {row?.message && (
                  <div style={{ fontSize: 11, color: C.muted, fontFamily: "'Share Tech Mono', monospace", marginTop: 2 }}>
                    {row.message}
                  </div>
                )}
              </div>
              <span style={{
                background: statusColor + "22", color: statusColor,
                border: `1px solid ${statusColor}55`,
                borderRadius: 4, padding: "2px 10px", fontSize: 11,
                fontFamily: "'Share Tech Mono', monospace",
              }}>
                {row?.status || "not started"}
              </span>
            </div>
          );
        })}
      </SettingsSection>

      {/* Log Collection Agents */}
      <SettingsSection title="📡  Log Collection Agents">
        {AGENTS.map(agent => {
          const eventsCount = srcCounts[agent.id] ?? null;
          return (
            <div key={agent.id} style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "14px 0", borderBottom: `1px solid ${C.border + "80"}`,
            }}>
              <div>
                <span style={{ fontSize: 13, color: C.text }}>{agent.icon} {agent.label}</span>
                <div style={{ fontSize: 11, color: C.muted, fontFamily: "'Share Tech Mono', monospace", marginTop: 2 }}>
                  {agent.desc}
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                {eventsCount !== null && (
                  <span style={{ color: C.accent, fontFamily: "'Share Tech Mono', monospace", fontSize: 12 }}>
                    {eventsCount} events/24h
                  </span>
                )}
                <StatusBadge ok={eventsCount !== null} labels={["Collecting", "No Data"]} />
              </div>
            </div>
          );
        })}
      </SettingsSection>

      {/* Detection Rules */}
      <SettingsSection title="🛡️  Detection Rules">
        {[
          { name: "SSH Brute Force",      threshold: "5 failures / 60s", severity: "CRITICAL" },
          { name: "HTTP Port Scan",        threshold: "20 x 4xx / 30s",  severity: "HIGH"     },
          { name: "SQL Injection",         threshold: "Instant",          severity: "CRITICAL" },
          { name: "Sensitive Path Access", threshold: "Instant",          severity: "HIGH"     },
          { name: "Root SSH Login",        threshold: "Instant",          severity: "CRITICAL" },
          { name: "OOM Kill",              threshold: "Instant",          severity: "MEDIUM"   },
          { name: "New User Created",      threshold: "Instant",          severity: "HIGH"     },
          { name: "Password Changed",      threshold: "Instant",          severity: "MEDIUM"   },
        ].map(rule => {
          const sevColors = { CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.yellow };
          const c = sevColors[rule.severity] || C.muted;
          return (
            <div key={rule.name} style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "12px 0", borderBottom: `1px solid ${C.border + "80"}`,
            }}>
              <span style={{ fontSize: 13, color: C.text }}>{rule.name}</span>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span style={{ fontSize: 11, color: C.muted, fontFamily: "'Share Tech Mono', monospace" }}>
                  {rule.threshold}
                </span>
                <span style={{
                  background: c + "22", color: c, border: `1px solid ${c}55`,
                  borderRadius: 4, padding: "1px 8px", fontSize: 10,
                  fontFamily: "'Share Tech Mono', monospace",
                }}>
                  {rule.severity}
                </span>
              </div>
            </div>
          );
        })}
      </SettingsSection>

      {/* Environment note */}
      <div style={{
        background: C.surface, border: `1px solid ${C.border}`,
        borderRadius: 8, padding: "14px 20px",
        fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: C.muted, lineHeight: 1.8,
      }}>
        <div style={{ color: C.accent, marginBottom: 4 }}>⚙️ Configuration</div>
        <div>Set <code style={{ color: C.text }}>VITE_API_URL</code> in <code style={{ color: C.text }}>frontend/.env</code> to point to your Flask backend.</div>
        <div>Set <code style={{ color: C.text }}>GEMINI_API_KEY</code> / <code style={{ color: C.text }}>ANTHROPIC_API_KEY</code> in <code style={{ color: C.text }}>backend/.env</code> for AI analysis.</div>
      </div>
    </div>
  );
}
