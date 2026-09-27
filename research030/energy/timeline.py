"""Capture host evidence for one continuous, independently aligned CFN recording.

This module never communicates with FNB58. Its GUI owns the meter connection.
The MCU link must support command(line, expected_events).
"""
from __future__ import annotations
import contextlib
import hashlib
import json
import time
from pathlib import Path

PATTERNS = {
    'calibration_before': [2, 5, 3, 7],
    'validation_before': [3, 7, 2, 5],
    'validation_after': [5, 2, 7, 3],
    'calibration_after': [7, 3, 5, 2],
}

class EnergyTimeline:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.origin_ns = time.monotonic_ns()
        self.origin_utc_ns = time.time_ns()
        self.records = []
        self.emit('start', schema=1, measurement_origin='host_timing_only',
                  host_origin_monotonic_ns=self.origin_ns,
                  host_origin_utc_ns=self.origin_utc_ns)

    def now(self):
        return (time.monotonic_ns() - self.origin_ns) / 1e9

    def emit(self, event, **fields):
        item = dict(event=event, host_s=self.now(), **fields)
        self.records.append(item)
        with (self.directory / 'timeline.jsonl').open('a', encoding='utf-8') as out:
            out.write(json.dumps(item, allow_nan=False) + '\n')
            out.flush()
        return item

    def marker(self, link, marker_id):
        if marker_id not in PATTERNS:
            raise ValueError('Unknown frozen marker pattern')
        if any(r.get('marker_id') == marker_id and r['event'] == 'marker_pattern' for r in self.records):
            raise ValueError('Marker pattern may only be recorded once')
        # Do not burn or calibrate with flash writes. The firmware marker must
        # busy-loop a deterministic RAM/SHA workload; radio remains off.
        time.sleep(2)
        pulses=[]
        for i, duration in enumerate(PATTERNS[marker_id]):
            sent=self.now()
            reply=link.command('ENERGY_MARKER '+str(duration*1000), {'energy_marker'})
            received=self.now()
            device_us=reply.get('duration_us')
            if (reply.get('event') != 'energy_marker' or type(device_us) is not int
                    or not duration*.95 <= device_us/1e6 <= duration*1.10):
                raise ValueError('Unverified MCU energy marker: '+repr(reply))
            elapsed=device_us/1e6
            if received-sent < elapsed-0.001 or received-sent-elapsed > 1.0:
                raise ValueError('Marker host/device time disagreement or excessive transport uncertainty')
            # The busy interval occurs within transmission -> received reply.
            # These are conservative brackets, not exact CPU start/end times.
            uncertainty=max(0.,received-sent-elapsed)
            pulse=dict(start_host_s=[sent,sent+uncertainty],
                       end_host_s=[received-uncertainty,received],
                       duration_device_s=elapsed, response=reply)
            pulses.append(pulse)
            self.emit('marker_pulse', marker_id=marker_id, pulse_index=i, **pulse)
            time.sleep(2)
        self.emit('marker_pattern', marker_id=marker_id,
                  role='calibration' if marker_id.startswith('calibration') else 'validation',
                  pulses=pulses)

    def baseline(self, seconds=10., label='idle'):
        if seconds < 10:
            raise ValueError('Baseline must be at least 10 seconds')
        start=self.now(); time.sleep(seconds)
        return self.emit('baseline', id=label, start_host_s=start,
                         end_host_s=self.now(), serial_polling=False)

    @contextlib.contextmanager
    def update_block(self, block_id, policy, expected_updates, baseline_ids, **metadata):
        """Caller fills receipt['accepted_updates'] only after verifying updates.

        Scope must include final STATUS/inference and, for firmware, reboot.
        Provisioning/cleaning stays outside this context.
        """
        if type(expected_updates) is not int or expected_updates <= 0:
            raise ValueError('Positive predeclared accepted update count required')
        receipt={}; start=self.now()
        self.emit('update_intent', id=block_id, start_host_s=start, policy=policy,
                  expected_updates=expected_updates, baseline_ids=baseline_ids, **metadata)
        try:
            yield receipt
            if receipt.get('accepted_updates') != expected_updates:
                raise ValueError('Accepted update count differs from predeclared count')
            self.emit('update_block', id=block_id, start_host_s=start,
                      end_host_s=self.now(), policy=policy,
                      accepted_updates=expected_updates, baseline_ids=baseline_ids, **metadata)
        except BaseException as exc:
            self.emit('update_failed', id=block_id, error=type(exc).__name__+': '+str(exc))
            raise

    def finish(self):
        ids=[r['marker_id'] for r in self.records if r['event']=='marker_pattern']
        if ids != list(PATTERNS):
            raise ValueError('Four calibration/validation patterns in frozen order required')
        if any(r['event']=='update_failed' for r in self.records):
            raise ValueError('Cannot finalize a failed energy series')
        self.emit('complete', energy_measured=False,
                  energy_analysis_pending=True,
                  note='A continuous CFN and validated time alignment are still required')
        data=(self.directory/'timeline.jsonl').read_bytes()
        spec=dict(schema=1, status='host_capture_complete',
                  source_sha256=hashlib.sha256(data).hexdigest(),
                  host_origin_monotonic_ns=self.origin_ns,
                  host_origin_utc_ns=self.origin_utc_ns,
                  marker_patterns=[r for r in self.records if r['event']=='marker_pattern'],
                  baselines=[r for r in self.records if r['event']=='baseline'],
                  blocks=[r for r in self.records if r['event']=='update_block'],
                  energy_measured=False)
        (self.directory/'energy_windows.json').write_text(json.dumps(spec,indent=2,allow_nan=False)+'\n',encoding='utf-8')
        return spec
