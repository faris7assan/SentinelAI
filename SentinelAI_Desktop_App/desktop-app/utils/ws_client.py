import json
import time
from PyQt5.QtCore import pyqtSignal, QThread


class WSClient(QThread):
    connected = pyqtSignal()
    disconnected = pyqtSignal()
    message_received = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url
        self.ws = None
        self._running = True

    def run(self):
        try:
            import websocket
        except ImportError:
            self.error.emit("websocket-client not installed")
            return

        def on_message(ws, message):
            try:
                data = json.loads(message)
                self.message_received.emit(data)
            except Exception as e:
                self.error.emit(f"WS Parse error: {e}")

        def on_error(ws, err):
            self.error.emit(str(err))

        def on_close(ws, close_status_code, close_msg):
            self.disconnected.emit()

        def on_open(ws):
            self.connected.emit()

        reconnect_delay = 3
        max_delay = 60
        while self._running:
            try:
                self.ws = websocket.WebSocketApp(
                    self.url,
                    on_open=on_open,
                    on_message=on_message,
                    on_error=on_error,
                    on_close=on_close,
                )
                self.ws.run_forever(ping_interval=30, ping_timeout=10)
            except Exception:
                pass
            if self._running:
                time.sleep(reconnect_delay)
                # Exponential backoff capped at max_delay
                reconnect_delay = min(reconnect_delay * 2, max_delay)

    def stop(self):
        self._running = False
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
