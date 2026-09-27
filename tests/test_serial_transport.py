"""Serial startup framing regressions; simulated I/O, never MCU evidence."""
from collections import deque
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host"))
from ids_update_lab import serial_runner as runner


class FakeSerialError(OSError):
    pass


class FakeSerial:
    def __init__(self, *, port, baudrate, timeout, write_timeout, initial=(), reply=None):
        if port is not None:
            raise AssertionError("serial must be created closed before setting DTR/RTS")
        self.port, self.timeout = port, timeout
        self.dtr = self.rts = True
        self.open_states = []
        self.chunks = deque(initial)
        self.writes = []
        self.reply = reply

    def open(self):
        self.open_states.append((self.port, self.dtr, self.rts))
        if self.dtr or self.rts:
            raise AssertionError("DTR and RTS must both be false BEFORE open")

    @property
    def in_waiting(self):
        return len(self.chunks[0]) if self.chunks and isinstance(self.chunks[0], bytes) else 0

    def read(self, size):
        if self.chunks:
            item = self.chunks.popleft()
            if isinstance(item, Exception):
                raise item
            return item
        time.sleep(min(self.timeout, 0.002))
        return b""

    def write(self, data):
        self.writes.append(data)
        if self.reply:
            response = self.reply(data)
            if response:
                self.chunks.append(response)

    def flush(self):
        pass

    def close(self):
        pass


def serial_module(factory):
    return SimpleNamespace(Serial=factory, SerialException=FakeSerialError)


class SerialTransportTests(unittest.TestCase):
    def test_partial_bytes_survive_timeout_until_real_newline(self):
        fake = None
        def factory(**kwargs):
            nonlocal fake
            fake = FakeSerial(**kwargs, initial=[b'{"event":"sta'])
            return fake
        raw = []
        with patch.dict(sys.modules, {"serial": serial_module(factory)}):
            transport = runner.SerialTransport("COM13", on_read=raw.append)
            self.assertIsNone(transport.readline(0.01))
            self.assertEqual(fake.open_states, [("COM13", False, False)])
            fake.chunks.extend([b'tus","ready":', b'true}\r\n'])
            self.assertEqual(transport.readline(0.03), '{"event":"status","ready":true}')
            self.assertEqual(b"".join(raw), b'{"event":"status","ready":true}\r\n')

    def test_reconnect_uses_closed_configuration_and_keeps_fragment(self):
        created = []
        def factory(**kwargs):
            chunks = [b'{"event":"', FakeSerialError("USB restart")] if not created else [b'boot"}\n']
            instance = FakeSerial(**kwargs, initial=chunks)
            created.append(instance)
            return instance
        with patch.dict(sys.modules, {"serial": serial_module(factory)}):
            transport = runner.SerialTransport("COM13")
            self.assertEqual(transport.readline(0.1), '{"event":"boot"}')
        self.assertEqual(len(created), 2)
        self.assertTrue(all(f.open_states == [("COM13", False, False)] for f in created))

    def test_startup_truncated_boot_is_recorded_before_safe_probe(self):
        created = []
        def factory(**kwargs):
            instance = FakeSerial(**kwargs, initial=[b'\x00{"event":"boot","release"'],
                reply=lambda data: b'{"event":"status","ready":true}\n' if data == b"STATUS\n" else None)
            created.append(instance)
            return instance
        logs = []
        with patch.dict(sys.modules, {"serial": serial_module(factory)}):
            transport = runner.SerialTransport("COM13")
            result, _ = runner.synchronize_serial(transport, logs.append, .1, startup_wait=.01, quiet_period=.005)
        self.assertEqual(result, {"event": "status", "ready": True})
        fragments = [r for r in logs if r.get("phase") == "startup_fragment"]
        self.assertEqual(len(fragments), 1)
        self.assertEqual(bytes.fromhex(fragments[0]["bytes_hex"]), b'\x00{"event":"boot","release"')
        self.assertIs(fragments[0]["complete_line"], False)
        self.assertEqual(created[0].writes, [b"\n", b"STATUS\n"])

    def test_corrupted_complete_frame_is_not_salvaged_and_status_is_retried(self):
        count = 0
        def reply(data):
            nonlocal count
            if data != b"STATUS\n":
                return None
            count += 1
            if count == 1:
                return b'{"event":"boot","release"{"event":"status","ready":false}\n'
            return b'{"event":"status","ready":true}\n'
        logs = []
        with patch.dict(sys.modules, {"serial": serial_module(lambda **kw: FakeSerial(**kw, reply=reply))}):
            transport = runner.SerialTransport("COM13")
            result, _ = runner.synchronize_serial(transport, logs.append, .12, startup_wait=0, quiet_period=.003)
        self.assertTrue(result["ready"])
        self.assertEqual(count, 2)
        self.assertTrue(any('"release"{"event"' in r.get("line", "") for r in logs))

    def test_status_retries_are_bounded_and_issue_no_mutations(self):
        created = []
        def factory(**kwargs):
            fake = FakeSerial(**kwargs, reply=lambda data: b"\x00invalid\n" if data == b"STATUS\n" else None)
            created.append(fake)
            return fake
        with patch.dict(sys.modules, {"serial": serial_module(factory)}):
            transport = runner.SerialTransport("COM13")
            with self.assertRaisesRegex(RuntimeError, "bounded STATUS"):
                runner.synchronize_serial(transport, lambda row: None, .15, attempts=3, startup_wait=0, quiet_period=.003)
        self.assertEqual(created[0].writes.count(b"STATUS\n"), 3)
        self.assertEqual(set(created[0].writes), {b"STATUS\n", b"\n"})

    def test_run_never_retries_lost_infer_or_update_response(self):
        experiment = Path(__file__).resolve().parents[1] / "examples" / "synthetic_demo"
        row = json.loads((experiment / "golden.jsonl").read_text().splitlines()[0])
        provenance = json.loads((experiment / "provenance.json").read_text())
        payload_hash = hashlib.sha256((experiment / "release-A.sids").read_bytes()[16:-256]).hexdigest()
        status = {"event": "status", "ready": True, "version": 1, "release": "synthetic-A", "schema": provenance["schema_sha256"],
            "bundle_sha256": payload_hash, "data_origin": "synthetic_plumbing", "chip": "esp32s3", "policy": "bundle"}
        inference = {**status, **row["expected_A"], "event": "inference", "latency_us": 1}
        original_sync = runner.synchronize_serial
        def quick_sync(transport, record, timeout):
            return original_sync(transport, record, timeout, startup_wait=0, quiet_period=.001)
        with tempfile.TemporaryDirectory() as temporary:
            for lost_command in (b"INFER", b"UPDATE"):
                instances = []
                def reply(data):
                    if data.startswith(lost_command):
                        return None
                    response = status if data == b"STATUS\n" else inference if data.startswith(b"INFER ") else None
                    return (json.dumps(response) + "\n").encode() if response else None
                def factory(**kwargs):
                    instance = FakeSerial(**kwargs, reply=reply)
                    instances.append(instance)
                    return instance
                args = SimpleNamespace(limit=1, repetitions=1, timeout=.03, port="COM13", model_only=False, native=None,
                    native_store=None, experiment=str(experiment), output=str(Path(temporary) / lost_command.decode()),
                    checkpoint="none", board_id="MOCK_ONLY", firmware_bin=None)
                with patch.dict(sys.modules, {"serial": serial_module(factory)}), patch.object(runner, "synchronize_serial", quick_sync):
                    with self.assertRaisesRegex(RuntimeError, "timeout waiting"):
                        runner.run(args)
                writes = instances[0].writes
                self.assertEqual(sum(data.startswith(lost_command) for data in writes), 1)
                if lost_command == b"INFER":
                    self.assertFalse(any(data.startswith(b"UPDATE") for data in writes))


if __name__ == "__main__":
    unittest.main()
