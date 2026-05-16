import { useState, useEffect } from "react";
import { C } from "../../config";

function LiveClock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return <span>{time.toLocaleTimeString()}</span>;
}

export function PageHeader({ page, pages, wsConnected }) {
  const current = pages.find(p => p.id === page);
  return (
    <div style={{
      marginBottom: 24, display: "flex",
      justifyContent: "space-between", alignItems: "flex-end",
    }}>
      <div>
        <div style={{
          fontSize: 11, color: C.muted, letterSpacing: 2,
          textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace",
        }}>
          SIEM · SecureWatch AI
        </div>
        <h1 style={{
          fontSize: 26, fontWeight: 700, color: C.text,
          marginTop: 4, letterSpacing: -0.5,
        }}>
          {current?.label}
        </h1>
      </div>
      <div style={{
        fontSize: 11, color: C.muted,
        fontFamily: "'Share Tech Mono', monospace", textAlign: "right",
      }}>
        <div>{new Date().toLocaleDateString()}</div>
        <div style={{ color: C.accent }}><LiveClock /></div>
        <div style={{
          marginTop: 2,
          color: wsConnected ? C.green : C.yellow,
          fontSize: 10,
        }}>
          {wsConnected ? "● LIVE" : "○ POLLING"}
        </div>
      </div>
    </div>
  );
}
