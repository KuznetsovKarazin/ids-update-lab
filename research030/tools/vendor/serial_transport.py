"""Reviewed serial buffering and safe startup from stage025, copied unchanged."""
import json
import time

class SerialTransport:
    def __init__(self, port, on_read=None):
        try:
            import serial
        except ImportError as exc:
            raise RuntimeError("pyserial is required for physical MCU transport: python -m pip install pyserial") from exc
        self.serial_module, self.port = serial, port
        self.on_read = on_read
        self.pending = bytearray()
        self.received_bytes = 0
        self.connection = self._open()

    def _open(self):
        # Opening with default asserted modem lines can reset an ESP32-S3.
        # Set both levels while the object is CLOSED, including on reconnect.
        connection = self.serial_module.Serial(port=None, baudrate=115200, timeout=0.05, write_timeout=3)
        connection.dtr = False
        connection.rts = False
        connection.port = self.port
        connection.open()
        return connection

    def write(self, line):
        self.connection.write((line + "\n").encode("ascii"))
        self.connection.flush()

    def readline(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if b"\n" in self.pending:
                frame, _, remainder = self.pending.partition(b"\n")
                self.pending = bytearray(remainder)
                return frame.rstrip(b"\r").decode("utf-8", errors="replace")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                self.connection.timeout = min(0.05, remaining)
                chunk = self.connection.read(max(1, min(self.connection.in_waiting, 4096)))
                if chunk:
                    self.received_bytes += len(chunk)
                    self.pending.extend(chunk)
                    if self.on_read:
                        self.on_read(chunk)
            except (self.serial_module.SerialException, OSError):
                self.connection.close()
                # USB Serial/JTAG may temporarily disconnect during software reset.
                while time.monotonic() < deadline:
                    try:
                        self.connection = self._open()
                        break
                    except (self.serial_module.SerialException, OSError):
                        time.sleep(0.1)

    def take_pending_fragment(self):
        """Explicit framing boundary ONLY; caller must record returned bytes."""
        fragment = bytes(self.pending)
        self.pending.clear()
        return fragment

    def close(self):
        self.connection.close()


def synchronize_serial(transport, record, timeout, attempts=3, startup_wait=2.0, quiet_period=0.2):
    """Read-only startup handshake; malformed frames are logged, never salvaged.

    Startup is drained for at least startup_wait, with at most one extra quiet
    period. STATUS probes share a separate total `timeout` budget. Only this safe
    query is retried. No UPDATE/INFER/reboot/erase is issued by this function.
    """
    if attempts < 1 or timeout <= 0 or startup_wait < 0 or quiet_period <= 0:
        raise ValueError("invalid serial synchronization limits")

    def log_line(line, **extra):
        record({"utc_ns": time.time_ns(), "direction": "rx", "line": line, **extra})

    def drain(settle):
        began = time.monotonic()
        last_activity = began
        seen = transport.received_bytes
        deadline = began + settle + quiet_period
        while time.monotonic() < deadline:
            line = transport.readline(min(0.05, max(0.001, deadline - time.monotonic())))
            now = time.monotonic()
            if transport.received_bytes != seen or line is not None:
                seen = transport.received_bytes
                last_activity = now
            if line is not None:
                log_line(line, phase="startup_drain")
            if now - began >= settle and now - last_activity >= quiet_period:
                break
        # A missing newline cannot become a protocol frame merely by timing out.
        # Startup synchronization explicitly closes that fragment and preserves it.
        fragment = transport.take_pending_fragment()
        if fragment:
            log_line(fragment.decode("utf-8", errors="replace"), complete_line=False,
                bytes_hex=fragment.hex(), phase="startup_fragment", reason="explicit_startup_framing_boundary")

    drain(startup_wait)
    overall_deadline = time.monotonic() + timeout
    for attempt in range(1, attempts + 1):
        remaining = overall_deadline - time.monotonic()
        if remaining <= 0:
            break
        if attempt > 1:
            # Preserve late/partial bytes from the failed safe probe before
            # establishing the next boundary. Nothing is silently flushed.
            drain(0.0)
            remaining = overall_deadline - time.monotonic()
            if remaining <= 0:
                break
        start = time.perf_counter_ns()
        for line in ("", "STATUS"):
            record({"utc_ns": time.time_ns(), "direction": "tx", "line": line,
                "phase": "startup_sync", "attempt": attempt})
            transport.write(line)
        attempt_deadline = time.monotonic() + remaining / (attempts - attempt + 1)
        while time.monotonic() < attempt_deadline:
            line = transport.readline(min(0.05, max(0.001, attempt_deadline - time.monotonic())))
            if line is None:
                continue
            log_line(line, phase="startup_sync", attempt=attempt)
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(response, dict) and response.get("event") == "status":
                return response, time.perf_counter_ns() - start
        record({"utc_ns": time.time_ns(), "direction": "host", "event": "startup_status_timeout", "attempt": attempt})
    raise RuntimeError("serial startup synchronization failed after bounded STATUS probes; inspect transcript.jsonl")

