"""Append-only serial evidence and strict no-mutation-retry link from stage018."""
import json
import time
from pathlib import Path

def now():return {"utc_ns":time.time_ns(),"monotonic_ns":time.monotonic_ns()}

class Evidence:
    def __init__(self, output):
        self.output = Path(output)
        self.phase = "startup"
        self.streams = {name: (self.output / (name + ".jsonl")).open("x", encoding="utf-8")
                        for name in ("transcript", "events", "observations")}

    def record(self, item, stream="transcript"):
        item = {**now(), "phase": self.phase, **item}
        self.streams[stream].write(json.dumps(item, allow_nan=False) + "\n")
        self.streams[stream].flush()
        return item

    def event(self, event, **fields):
        return self.record({"event": event, **fields}, "events")

    def close(self):
        for stream in self.streams.values():
            stream.close()


class Link:
    def __init__(self, api, evidence, timeout):
        self.api, self.evidence, self.timeout = api, evidence, timeout
        self.transport = None
        self.allow_reconnect = False
        self.opens = 0

    def open(self, port):
        owner = self
        class ObservedTransport(self.api.SerialTransport):
            def _open(inner):
                owner.opens += 1
                owner.evidence.record({"direction": "host", "event": "serial_open_attempt", "attempt": owner.opens})
                if owner.opens > 1 and not owner.allow_reconnect:
                    raise RuntimeError("Unexpected serial disconnect: no reconnect or command retry")
                return super()._open()
        self.transport = ObservedTransport(port, on_read=lambda data: self.evidence.record(
            {"direction": "rx_bytes", "bytes_hex": data.hex()}))
        status, _ = self.api.synchronize_serial(self.transport, self.evidence.record, self.timeout)
        return status

    def receive(self, expected):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            line = self.transport.readline(min(.1, max(.001, deadline - time.monotonic())))
            if line is None:
                continue
            self.evidence.record({"direction": "rx", "line": line})
            try:
                result = json.loads(line, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
            except ValueError as exc:
                if self.allow_reconnect and expected == {"boot"} and not line.lstrip().startswith(("{", "[")):
                    continue  # Plain ESP-IDF boot text is preserved in the transcript.
                raise RuntimeError("Malformed protocol response; command will not be retried") from exc
            if not isinstance(result, dict) or result.get("event") not in expected:
                raise RuntimeError("Unexpected protocol event; command will not be retried: " + line)
            return result
        raise TimeoutError("No expected protocol response; command will not be retried")

    def command(self, line, expected):
        self.evidence.record({"direction": "tx", "line": line})
        start = time.monotonic_ns()
        self.transport.write(line)
        reply = self.receive(set(expected))
        self.evidence.event("command_response", command_kind=line.split(" ", 1)[0], response=reply,
                            tx_wire_bytes=len((line + "\n").encode("ascii")), host_roundtrip_ns=time.monotonic_ns() - start)
        return reply

    def close(self):
        if self.transport:
            fragment = self.transport.take_pending_fragment()
            if fragment:
                self.evidence.record({"direction": "rx", "bytes_hex": fragment.hex(), "complete_line": False,
                                      "line": fragment.decode("utf-8", errors="replace"), "phase": "session_end_fragment"})
            self.transport.close()
            self.transport = None

