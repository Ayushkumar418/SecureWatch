import { useState } from "react";
import { API, C } from "./config";
import { useFetch } from "./hooks/useFetch";
import { useSocket } from "./hooks/useSocket";
import { ScanLine } from "./components/ui/ScanLine";
import { Sidebar, PAGES } from "./components/layout/Sidebar";
import { PageHeader } from "./components/layout/PageHeader";
import Overview  from "./pages/Overview";
import LiveEvents from "./pages/LiveEvents";
import Alerts    from "./pages/Alerts";
import ThreatMap from "./pages/ThreatMap";
import Reports   from "./pages/Reports";
import Settings  from "./pages/Settings";

// Global styles injected once
const GLOBAL_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;500;600;700&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0a0e1a; }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: #0a0e1a; }
  ::-webkit-scrollbar-thumb { background: #1e2d50; border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: #2a3f6e; }
  select option { background: #0f1628; }
  button { font-family: inherit; }
  @keyframes scanline {
    0%   { transform: translateX(-100%); }
    100% { transform: translateX(100vw); }
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.4; }
  }
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes slideIn {
    from { opacity: 0; transform: translateX(-8px); }
    to   { opacity: 1; transform: translateX(0); }
  }
  @keyframes flashIn {
    0%   { background: rgba(0, 212, 255, 0.15); }
    100% { background: transparent; }
  }
`;

export default function App() {
  const [page, setPage] = useState("overview");
  const { data: stats } = useFetch(`${API}/stats`);
  const ws = useSocket();
  const critCount = stats?.alerts_by_severity?.CRITICAL || 0;

  const pageComponents = {
    overview:  <Overview ws={ws} />,
    events:    <LiveEvents ws={ws} />,
    alerts:    <Alerts ws={ws} />,
    threatmap: <ThreatMap />,
    reports:   <Reports />,
    settings:  <Settings ws={ws} />,
  };

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: "'Syne', sans-serif" }}>
      <style>{GLOBAL_CSS}</style>
      <ScanLine />
      <Sidebar page={page} setPage={setPage} critCount={critCount} wsConnected={ws.connected} />

      {/* Main content area */}
      <div style={{ marginLeft: 224, padding: "28px 32px", animation: "fadeIn 0.3s ease" }}
        key={page}
      >
        <PageHeader page={page} pages={PAGES} wsConnected={ws.connected} />
        {pageComponents[page] ?? null}
      </div>
    </div>
  );
}
