#!/usr/bin/env python3
"""Strict read-only CFN decoder and numerical diagnostics; Python standard library.

Header/channel interpretation cross-checked against didim99/usbmeter-utils,
commit 38696ff58c469b556927e508319620b8914521f7 (community reverse engineering).
Integrals use recorded relative time, not independently established wall time.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics
import struct

CHANNELS = {0: ("voltage_V", "V"), 1: ("current_A", "A"),
            2: ("d_plus_V", "V"), 3: ("d_minus_V", "V"),
            4: ("power_W", "W"), 5: ("reported_capacity_Ah", "Ah"),
            6: ("reported_energy_Wh", "Wh")}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def decode(data):
    require(len(data) >= 26, "Truncated CFN header")
    rate, start_ma, stop_ma, stop_s, channels = struct.unpack_from("<diiih", data)
    require(math.isfinite(rate) and rate > 0 and 1 <= channels <= 7,
            "Unsupported nominal rate/channel count")
    pos, descriptors, seen = 22, [], set()
    for _ in range(channels):
        require(pos + 7 <= len(data), "Truncated channel descriptor")
        kind, color, bounds = struct.unpack_from("<hIB", data, pos)
        pos += 7
        require(kind in CHANNELS and kind not in seen and bounds in (0, 1),
                "Unknown/duplicate channel or invalid bounds flag")
        seen.add(kind)
        name, unit = CHANNELS[kind]
        channel = dict(id=kind, name=name, unit=unit, color_argb=f"{color:08x}")
        if bounds:
            require(pos + 16 <= len(data), "Truncated bounds")
            hi, lo = struct.unpack_from("<dd", data, pos)
            require(math.isfinite(lo) and math.isfinite(hi) and lo <= hi,
                    "Invalid extrema in header")
            channel.update(header_min=lo, header_max=hi)
            pos += 16
        descriptors.append(channel)
    require(pos + 4 <= len(data), "Missing data count")
    count, = struct.unpack_from("<i", data, pos)
    pos += 4
    width = 8 * (channels + 1)
    require(count >= 2 and len(data) == pos + count * width,
            "Data count does not match exact file length")
    names = ["relative_time_s"] + [d["name"] for d in descriptors]
    rows = [dict(zip(names, values)) for values in
            struct.iter_unpack("<" + "d" * (channels + 1), data[pos:])]
    require(all(math.isfinite(v) for r in rows for v in r.values()), "Nonfinite data")
    require(all(b["relative_time_s"] > a["relative_time_s"] for a, b in zip(rows, rows[1:])),
            "Repeated or decreasing relative time")
    for desc in descriptors:
        if "header_min" in desc:
            values = [r[desc["name"]] for r in rows]
            require(math.isclose(min(values), desc["header_min"], abs_tol=1e-12)
                    and math.isclose(max(values), desc["header_max"], abs_tol=1e-12),
                    "Header extrema differ from recorded samples")
    return {"nominal_rate_sps": rate, "start_current_condition_mA": start_ma,
            "stop_current_condition_mA": stop_ma, "stop_time_condition_s": stop_s,
            "channels": descriptors, "data_offset": pos, "row_bytes": width,
            "count": count}, rows


def analyze(header, rows):
    require(all(name in rows[0] for name in ("voltage_V", "current_A")),
            "Voltage/current are required for integration")
    t = [r["relative_time_s"] for r in rows]
    dt = [b-a for a, b in zip(t, t[1:])]
    duration = t[-1] - t[0]
    power = [r["voltage_V"] * r["current_A"] for r in rows]
    energy_steps = [(a+b)*0.5*d for a, b, d in zip(power, power[1:], dt)]
    charge_steps = [(a["current_A"]+b["current_A"])*0.5*d
                    for a, b, d in zip(rows, rows[1:], dt)]
    energy, charge = math.fsum(energy_steps), math.fsum(charge_steps)
    summary = {"format_check": "PASS", "nominal_time_integral_only": True,
               "header": header, "recorded_span_s": duration,
               "dt_s": {"min": min(dt), "median": statistics.median(dt), "max": max(dt)},
               "grid_rate_sps": (len(rows)-1)/duration,
               "max_grid_deviation_s": max(abs(v-(t[0]+i/header["nominal_rate_sps"]))
                                            for i, v in enumerate(t)),
               "integrated_UI_J": energy, "integrated_UI_Wh": energy/3600,
               "integrated_I_C": charge, "time_weighted_current_A": charge/duration,
               "time_weighted_power_W": energy/duration,
               "channel_statistics": {},
               "meter_clock_aligned_to_host": False,
               "independent_sampling_rate_verified": False,
               "measurement_accuracy_calibrated": False,
               "energy_update_measured": False}
    for name in rows[0]:
        values = [r[name] for r in rows]
        summary["channel_statistics"][name] = {"min": min(values), "max": max(values),
                                              "mean": statistics.mean(values)}
    if "power_W" in rows[0]:
        summary["max_power_minus_UI_W"] = max(abs(r["power_W"]-p) for r, p in zip(rows, power))
    if "reported_capacity_Ah" in rows[0]:
        differences = [(b["reported_capacity_Ah"]-a["reported_capacity_Ah"])*3600
                       for a, b in zip(rows, rows[1:])]
        summary["capacity_increment_max_error_C"] = max(abs(a-b) for a, b in zip(differences, charge_steps))
        summary["reported_capacity_delta_C"] = (rows[-1]["reported_capacity_Ah"]-rows[0]["reported_capacity_Ah"])*3600
    if "reported_energy_Wh" in rows[0]:
        reported = (rows[-1]["reported_energy_Wh"]-rows[0]["reported_energy_Wh"])*3600
        summary["reported_energy_delta_J"] = reported
        summary["UI_to_reported_energy_ratio"] = energy/reported if reported else None
        summary["energy_counter_consistent_with_UI"] = math.isclose(reported, energy, rel_tol=1e-3, abs_tol=1e-9)
    summary["limitations"] = [
        "Channel units follow a community format description, not a manufacturer calibration certificate.",
        "Perfect nominal time spacing does not establish physical sampling rate or absence of dropped/filtered samples.",
        "No absolute timestamp in CFN; no exact alignment of any host interval is asserted.",
        "Reported energy is preserved unchanged; no ad hoc factor-four correction is applied.",
        "USB connection state and wiring affect the baseline; a whole-file integral alone is not a single-update energy measurement."]
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file", type=Path)
    p.add_argument("--output", type=Path, required=True, help="New directory")
    args = p.parse_args()
    data = args.file.read_bytes()
    header, rows = decode(data)
    result = analyze(header, rows)
    result.update(source_file=args.file.name, source_bytes=len(data),
                  source_sha256=hashlib.sha256(data).hexdigest())
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2,
                                                       allow_nan=False) + "\n", encoding="utf-8")
    with (args.output / "samples.jsonl").open("x", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, allow_nan=False) + "\n")
    print(json.dumps({k: result[k] for k in ("format_check", "recorded_span_s", "integrated_UI_J",
                      "reported_energy_delta_J", "energy_counter_consistent_with_UI")}))


if __name__ == "__main__":
    main()
