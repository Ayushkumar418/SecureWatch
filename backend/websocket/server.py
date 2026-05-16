"""
server.py — Socket.IO WebSocket server for real-time event streaming.

Events pushed to clients:
  • "new_event"    — every new log event
  • "new_alert"    — every new alert created by detection engine
  • "stats_update" — periodic dashboard stats refresh
"""
import logging

log = logging.getLogger("websocket")

# The SocketIO instance — initialized by init_websocket()
_socketio = None


def init_websocket(app):
    """Initialize Socket.IO with the Flask app."""
    global _socketio
    try:
        from flask_socketio import SocketIO
        _socketio = SocketIO(
            app,
            cors_allowed_origins="*",
            async_mode="threading",     # use threading (compatible everywhere)
            logger=False,
            engineio_logger=False,
        )
        log.info("✅ WebSocket server initialized (Socket.IO)")

        @_socketio.on("connect", namespace="/live")
        def on_connect():
            log.info("Client connected to /live")

        @_socketio.on("disconnect", namespace="/live")
        def on_disconnect():
            log.info("Client disconnected from /live")

        return _socketio

    except ImportError:
        log.warning("flask-socketio not installed — WebSocket disabled (using HTTP polling)")
        return None


def get_socketio():
    """Get the SocketIO instance (or None if not initialized)."""
    return _socketio


def broadcast_event(event_data: dict):
    """Broadcast a new event to all connected clients."""
    if _socketio:
        try:
            # Ensure timestamp is serializable
            data = {**event_data}
            if hasattr(data.get("timestamp"), "isoformat"):
                data["timestamp"] = data["timestamp"].isoformat()
            _socketio.emit("new_event", data, namespace="/live")
        except Exception as e:
            log.debug("WebSocket broadcast failed: %s", e)


def broadcast_alert(alert_data: dict):
    """Broadcast a new alert to all connected clients."""
    if _socketio:
        try:
            _socketio.emit("new_alert", alert_data, namespace="/live")
        except Exception as e:
            log.debug("WebSocket alert broadcast failed: %s", e)


def broadcast_stats(stats_data: dict):
    """Broadcast updated stats to all connected clients."""
    if _socketio:
        try:
            _socketio.emit("stats_update", stats_data, namespace="/live")
        except Exception as e:
            log.debug("WebSocket stats broadcast failed: %s", e)
