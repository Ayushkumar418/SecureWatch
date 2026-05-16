import { useEffect, useState, useRef, useCallback } from "react";
import { io } from "socket.io-client";
import { API } from "../config";

/**
 * useSocket — connects to the Socket.IO /live namespace
 * and exposes real-time event/alert streams.
 *
 * Falls back gracefully if the server doesn't support WebSocket.
 */
export function useSocket() {
  const [connected, setConnected] = useState(false);
  const [liveEvents, setLiveEvents] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [liveStats, setLiveStats]   = useState(null);
  const socketRef = useRef(null);

  useEffect(() => {
    const url = API.replace("/api", "");
    const s = io(url, {
      path: "/socket.io",
      transports: ["websocket", "polling"],
      reconnectionAttempts: 5,
      reconnectionDelay: 2000,
      timeout: 5000,
      autoConnect: true,
    });

    s.on("connect", () => {
      console.log("[WS] Connected to SecureWatch");
      setConnected(true);
    });

    s.on("disconnect", () => {
      console.log("[WS] Disconnected");
      setConnected(false);
    });

    s.on("connect_error", () => {
      setConnected(false);
    });

    // Live event stream
    s.on("new_event", (data) => {
      setLiveEvents(prev => [data, ...prev].slice(0, 200));
    });

    // Live alert stream
    s.on("new_alert", (data) => {
      setLiveAlerts(prev => [data, ...prev].slice(0, 50));
    });

    // Stats updates
    s.on("stats_update", (data) => {
      setLiveStats(data);
    });

    socketRef.current = s;

    return () => {
      s.disconnect();
      socketRef.current = null;
    };
  }, []);

  const clearEvents = useCallback(() => setLiveEvents([]), []);
  const clearAlerts = useCallback(() => setLiveAlerts([]), []);

  return {
    socket: socketRef.current,
    connected,
    liveEvents,
    liveAlerts,
    liveStats,
    clearEvents,
    clearAlerts,
  };
}
