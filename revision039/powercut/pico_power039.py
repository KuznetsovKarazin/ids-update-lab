"""Pico 2 / MicroPython controller for phase-triggered supply cuts.

Original software: Oleksandr Kuznetsov. MIT license.
Copy as main.py, with reviewed powercut_config.json. Disabled by default.
GPIO controls an EXTERNAL active-high load switch; NEVER target power directly.
PIO issues the switch command, not a host or Python timer. ADC evidence does
not by itself locate the supply collapse inside a flash instruction/API call.
"""
import sys
import os
import time
import json
import select
import hashlib
import binascii
from machine import Pin, ADC
import rp2

CONFIG_PATH = "powercut_config.json"
PROTOCOL = "ids-power039-v1"


@rp2.asm_pio(set_init=rp2.PIO.OUT_HIGH)
def cut_program():
    # 1 MHz. After sampled rising edge: (delay + 1) loop cycles,
    # one phase-high check, then EN low: nominal delay + 3 us, plus input sync.
    pull(block)
    mov(x, osr)
    wait(0, pin, 0)
    wait(1, pin, 0)
    label("delay")
    jmp(x_dec, "delay")
    jmp(pin, "cut")
    set(x, 2)                 # Phase already ended: DO NOT cut.
    mov(isr, x)
    push(block)
    jmp("done")
    label("cut")
    set(pins, 0)
    set(x, 1)
    mov(isr, x)
    push(block)
    label("done")
    jmp("done")


@rp2.asm_pio()
def width_program():
    # 2 MHz, two cycles per high-count iteration. This is digital strobe
    # width, not independently calibrated flash or power-fall time.
    wait(0, pin, 0)
    wait(1, pin, 0)
    mov(x, invert(null))
    label("high")
    jmp(pin, "count")
    jmp("finish")
    label("count")
    jmp(x_dec, "high")
    label("finish")
    mov(isr, invert(x))
    push(block)
    label("done")
    jmp("done")


def emit(event, **fields):
    fields.update(event=event, controller_ticks_us=time.ticks_us())
    print(json.dumps(fields))


def main():
    try:
        config_bytes = open(CONFIG_PATH, "rb").read()
        cfg = json.loads(config_bytes)
        digest = binascii.hexlify(hashlib.sha256(config_bytes).digest()).decode()
    except Exception as exc:
        emit("controller_error", reason="missing_or_invalid_config", detail=str(exc))
        return
    pins = [cfg.get("enable_pin"), cfg.get("phase_pin"), cfg.get("adc_pin")]
    if len(set(pins)) != 3 or not all(type(x) is int for x in pins):
        emit("controller_error", reason="invalid_pins")
        return
    enable = Pin(pins[0], Pin.IN)  # external pull-down guarantees OFF at boot
    phase = Pin(pins[1], Pin.IN, Pin.PULL_DOWN)
    adc = ADC(Pin(pins[2], Pin.IN))
    armed = False
    task = None
    sm = None
    latest = None
    poll = select.poll()
    poll.register(sys.stdin, select.POLLIN)

    def identity():
        emit("controller_id", protocol=PROTOCOL, config_sha256=digest,
             enabled=cfg.get("enabled") is True, armed=armed,
             enable_pin=pins[0], phase_pin=pins[1], adc_pin=pins[2],
             machine=os.uname().machine, micropython=sys.version,
             pio_clock_hz=1000000, active_high_enable=True)

    def stop_sm():
        nonlocal sm
        if sm is not None:
            sm.active(0)
            sm = None

    def set_on(on):
        stop_sm()
        enable.init(Pin.OUT, value=1 if on else 0)

    def sample_rail(off_ms):
        start = time.ticks_us()
        points = []
        low_tick = None
        slope = cfg.get("adc_volts_per_count")
        zero = float(cfg.get("adc_zero_volts", 0.0))
        while time.ticks_diff(time.ticks_us(), start) < off_ms * 1000:
            elapsed = time.ticks_diff(time.ticks_us(), start)
            raw = adc.read_u16()
            if slope is not None and zero + float(slope) * raw <= cfg["rail_off_max_volts"]:
                if low_tick is None:
                    low_tick = elapsed
            # bounded trace: rapid initial sample window + 10 ms tail
            if elapsed < 10000 or not points or elapsed - points[-1][0] >= 10000:
                if len(points) < 4096:
                    points.append([elapsed, raw])
            time.sleep_us(20 if elapsed < 10000 else 1000)
        return points, low_tick

    identity()
    while True:
        if task is not None:
            if sm.rx_fifo():
                code = sm.get()
                job = task
                task = None
                observed = time.ticks_us()
                if job["mode"] == "measure":
                    stop_sm()
                    latest = dict(event="phase_width", trial=job["trial"],
                                  strobe_width_us=code, calibrated_timebase=False)
                    emit(**latest)
                elif code == 2:
                    set_on(True)
                    latest = dict(event="cut_result", trial=job["trial"],
                                  switch_command_issued=False, reason="phase_ended_before_switch",
                                  requested_delay_us=job["delay_us"], rail_samples=[])
                    emit(**latest)
                else:
                    # PIO has already set EN low. CPU receipt time is AFTER
                    # the actual edge; do not call it the physical cut instant.
                    set_on(False)
                    emit("cut_started", trial=job["trial"],
                         phase_high_at_switch_command=True,
                         nominal_pio_edge_delay_us=job["delay_us"] + 3)
                    points, low_tick = sample_rail(job["off_ms"])
                    set_on(True)
                    latest = dict(event="cut_result", trial=job["trial"],
                                  switch_command_issued=True,
                                  phase_high_at_switch_command=True,
                                  requested_delay_us=job["delay_us"],
                                  nominal_pio_edge_delay_us=job["delay_us"] + 3,
                                  switch_event_cpu_observed_ticks_us=observed,
                                  off_ms=job["off_ms"], rail_samples=points,
                                  first_low_from_cpu_observation_us=low_tick,
                                  rail_sample_clock_origin="after_cpu_observed_switch_event",
                                  power_restored=True,
                                  exact_flash_instruction_phase_verified=False)
                    emit(**latest)
            elif time.ticks_diff(time.ticks_ms(), task["armed_ms"]) >= task["timeout_ms"]:
                job = task
                task = None
                set_on(True)
                latest = dict(event="phase_timeout", trial=job["trial"], switch_command_issued=False)
                emit(**latest)
        if not poll.poll(0):
            time.sleep_us(20)
            continue
        parts = sys.stdin.readline().strip().split()
        try:
            if parts == ["ID"]:
                identity()
            elif parts == ["ADC"]:
                emit("adc", raw=adc.read_u16(), phase_level=phase.value())
            elif parts == ["LAST"]:
                if latest is None:
                    emit("controller_error", reason="no_result")
                else:
                    emit(**latest)
            elif parts == ["DISARM"]:
                task = None
                set_on(False)
                armed = False
                emit("disarmed", power_on=False)
            elif parts == ["ARM", "PHYSICAL"]:
                if cfg.get("enabled") is not True or cfg.get("active_high_enable") is not True:
                    raise ValueError("controller_disabled_or_unsupported_polarity")
                if task is not None:
                    raise ValueError("busy")
                set_on(True)
                armed = True
                emit("armed", power_on=True)
            elif not armed:
                raise ValueError("not_armed")
            elif task is not None:
                raise ValueError("busy")
            elif parts == ["ON"]:
                set_on(True)
                emit("power_on")
            elif len(parts) == 2 and parts[0] == "PROBE":
                off_ms = int(parts[1])
                if not 1000 <= off_ms <= 10000:
                    raise ValueError("off_ms")
                set_on(False)
                points, low_tick = sample_rail(off_ms)
                set_on(True)
                emit("probe_result", rail_samples=points, off_ms=off_ms,
                     first_low_from_cpu_observation_us=low_tick, power_restored=True)
            elif len(parts) == 3 and parts[0] == "MEASURE":
                token, timeout_ms = parts[1], int(parts[2])
                if not 100 <= timeout_ms <= 30000 or phase.value():
                    raise ValueError("timeout_or_phase_not_idle")
                sm = rp2.StateMachine(1, width_program, freq=2000000,
                                      in_base=phase, jmp_pin=phase)
                task = dict(mode="measure", trial=token, timeout_ms=timeout_ms,
                            armed_ms=time.ticks_ms())
                sm.active(1)
                emit("phase_armed", trial=token, mode="measure")
            elif len(parts) == 5 and parts[0] == "CUT":
                token, delay_us, off_ms, timeout_ms = parts[1], int(parts[2]), int(parts[3]), int(parts[4])
                if not 0 <= delay_us <= 1000000 or not 1000 <= off_ms <= 10000 or not 100 <= timeout_ms <= 30000 or phase.value():
                    raise ValueError("cut_bounds_or_phase_not_idle")
                sm = rp2.StateMachine(0, cut_program, freq=1000000,
                                      in_base=phase, jmp_pin=phase, set_base=enable)
                sm.put(delay_us)
                task = dict(mode="cut", trial=token, delay_us=delay_us,
                            off_ms=off_ms, timeout_ms=timeout_ms, armed_ms=time.ticks_ms())
                sm.active(1)
                emit("phase_armed", trial=token, mode="cut", requested_delay_us=delay_us)
            else:
                raise ValueError("bad_command")
        except Exception as exc:
            emit("controller_error", reason=str(exc))


if __name__ == "__main__":
    main()
