#!/usr/bin/env python3
"""Guarded setup and evidence packaging for revision039 physical-cut experiments.

Original software: Oleksandr Kuznetsov. MIT license.
This helper never flashes a device or starts the 200-trial campaign.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import statistics
import sys
import time
import zipfile

AUTHOR = "Oleksandr Kuznetsov"
PROTOCOL = "ids-power039-v1"


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for part in iter(lambda: f.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def fresh(path):
    path = Path(path)
    if path.exists():
        raise ValueError("Файл уже существует; выберите новое имя: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def save(path, data):
    with fresh(path).open("x", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, allow_nan=False)
        f.write("\n")


def ask_yes(prompt):
    answer = input(prompt + " [да/нет]: ").strip().lower()
    if answer not in ("да", "yes", "y", "д"):
        raise ValueError("Остановлено: условие не подтверждено. Ничего не включаем.")


def ask_voltage(prompt, low, high):
    value = float(input(prompt + " (В, только число): ").strip().replace(",", "."))
    if not math.isfinite(value) or not low <= value <= high:
        raise ValueError(f"Напряжение вне допустимого интервала {low}…{high} В: {value}")
    return value


def load_runner(kit):
    path = Path(kit) / "revision039/powercut/run_powercut039.py"
    spec = importlib.util.spec_from_file_location("bench045_original_runner", path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


class Link:
    """Pico ASCII/JSON interface. Does not toggle reset lines or retry commands."""
    def __init__(self, port, transcript=None):
        import serial
        self.log = None
        self.ser = None
        try:
            if transcript:
                self.log = fresh(transcript).open("x", encoding="utf-8", newline="\n")
            self.ser = serial.Serial(port=None, baudrate=115200, timeout=.25, write_timeout=3)
            # Pico native USB CDC: asserted DTR enables reliable terminal output.
            self.ser.dtr = True
            self.ser.rts = False
            self.ser.port = port
            self.ser.open()
        except Exception:
            self.close()
            raise

    def record(self, direction, line):
        if self.log:
            self.log.write(json.dumps(dict(utc_ns=time.time_ns(), direction=direction, line=line), ensure_ascii=False) + "\n")
            self.log.flush()

    def request(self, command, event, timeout=5):
        self.record("tx", command)
        self.ser.write((command + "\n").encode("ascii"))
        self.ser.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            raw = self.ser.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            self.record("rx", line)
            try:
                result = json.loads(line)
            except ValueError:
                continue
            if not isinstance(result, dict):
                continue
            if result.get("event") == "controller_error":
                raise RuntimeError("Pico: " + str(result))
            if result.get("event") == event:
                return result
        raise TimeoutError("Pico не ответил на " + command + "; команда не повторялась")

    def close(self):
        if self.ser is not None:
            self.ser.close()
        if self.log is not None:
            self.log.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def identity(link, config=None):
    info = link.request("ID", "controller_id")
    if info.get("protocol") != PROTOCOL:
        raise ValueError("Не тот контроллер: нужен ids-power039-v1")
    if config:
        cfg = read(config)
        if info.get("config_sha256") != sha(config):
            raise ValueError("Конфигурация Pico отличается от файла ПК. Скопируйте точный файл и перезагрузите Pico.")
        for key in ("enable_pin", "phase_pin", "adc_pin", "active_high_enable", "enabled"):
            if info.get(key) != cfg.get(key):
                raise ValueError("Pico/config mismatch: " + key)
    return info


def samples(link, count=64):
    vals = []
    for _ in range(count):
        raw = link.request("ADC", "adc").get("raw")
        if type(raw) is not int or not 0 <= raw <= 65535:
            raise ValueError("Некорректный raw ADC")
        vals.append(raw)
    return dict(raw=vals, n=count, mean=statistics.mean(vals), minimum=min(vals),
                maximum=max(vals), stdev=statistics.stdev(vals) if count > 1 else 0)


def fit_calibration(off, on, off_volts, on_volts):
    if not 0 <= off_volts <= .1 or not 3.0 <= on_volts <= 3.5:
        raise ValueError("Неверное напряжение калибровки")
    n0, n1 = off["mean"], on["mean"]
    if not all(math.isfinite(x) for x in (n0, n1, off_volts, on_volts)):
        raise ValueError("Non-finite calibration")
    # Broad gate for the intended 1:1 resistor divider, not an ADC accuracy claim.
    if not 18000 <= n1 <= 46000 or not 0 <= n0 <= 3000 or n1 - n0 < 15000:
        raise ValueError("ADC не соответствует ожидаемому делителю примерно 1:2; проверьте проводку и номиналы")
    slope = (on_volts - off_volts) / (n1 - n0)
    zero = off_volts - slope * n0
    if not 0 < slope < .01 or abs(zero) > .5:
        raise ValueError("Коэффициенты калибровки вне допуска")
    return dict(adc_volts_per_count=slope, adc_zero_volts=zero)


def init(args):
    kit = args.kit.resolve()
    source = kit / "revision039/powercut"
    cfg = read(source / "powercut_config.example.json")
    controller = (source / "pico_power039.py").read_bytes()
    args.output.mkdir(parents=True, exist_ok=False)
    cfg["bench045_kit"] = str(kit)
    cfg["bench045_original_author"] = AUTHOR
    cfg["enabled"] = False
    save(args.output / "disabled_config.json", cfg)
    with (args.output / "controller_main.py").open("xb") as f:
        f.write(controller)
    save(args.output / "SOURCE045.json", dict(original_author=AUTHOR, kit=str(kit),
         controller_source=str(source / "pico_power039.py"), controller_sha256=sha(args.output / "controller_main.py"),
         helper_sha256=sha(__file__), status="disabled_setup_only", hardware_access_attempted=False))
    return dict(status="initialized_disabled", output=str(args.output))


def identify(args):
    if args.output:
        fresh(args.output)
    with Link(args.port) as link:
        info = identity(link)
    if args.output:
        save(args.output, info)
    return info


def calibrate(args):
    fresh(args.output)
    cfg = read(args.config)
    if cfg.get("enabled") is not False:
        raise ValueError("Калибровка разрешена только с disabled_config.json (enabled=false)")
    transcript = args.output.with_name(args.output.stem + "-serial.jsonl")
    with Link(args.port, transcript) as link:
        ident = identity(link, args.config)
        link.request("DISARM", "disarmed")
        ask_yes("Провод GP15→EN отключён; делитель собран; общая земля есть; USB платы ESP32 сейчас отключён")
        off_v = ask_voltage("Мультиметром измерьте 3V3 ESP32 относительно GND при выключенной плате", 0, .1)
        off = samples(link)
        ask_yes("Подключите ESP32 напрямую к USB; EN по-прежнему отключён; проверьте режим вольтметра и щупы на 3V3/GND")
        on_v = ask_voltage("Напряжение 3V3 ESP32 мультиметром при включённой плате", 3.0, 3.5)
        adc_v = ask_voltage("Напряжение середины делителя (GP26) относительно GND мультиметром", .8, 2.3)
        on = samples(link)
        fit = fit_calibration(off, on, off_v, on_v)
        result = dict(schema="bench045_adc_calibration_v1", original_author=AUTHOR,
                      status="two_point_dmm_calibration", config_sha256=sha(args.config),
                      controller=ident, off_voltage=off_v, on_voltage=on_v, adc_input_on_voltage=adc_v,
                      off=off, on=on, **fit, hardware_access_attempted=True,
                      independent_analog_timing_verified=False, created_utc_ns=time.time_ns())
        save(args.output, result)
    print("Калибровка сохранена. Отключите прямой USB ESP32 перед сборкой цепи отключения питания.")
    return dict(status="calibrated", output=str(args.output), **fit)


CHECKS = (
    ("external_switch_accepts_3v3_enable", "Стоит TPS22919EVM; управление EN совместимо с логикой 3,3 В; вход питания стенда 5 В"),
    ("external_enable_pulldown", "EN/ON имеет внешний резистор 2,2 кОм к GND; перемычка принудительного ON снята согласно схеме"),
    ("common_ground", "GND Pico, TPS22919EVM, ESP32, USB-breakout и делителя соединены"),
    ("no_usb_vbus_bypass", "Прямого USB ПК→ESP32 нет: D+/D− проходят через USB-breakout, а VBUS идёт только через TPS22919EVM"),
    ("no_other_power_path", "К ESP32 не подключены второй USB-кабель, 5V/3V3 Pico или иной источник; питание ESP32 приходит только с VOUT ключа"),
    ("esp_not_powered_by_gpio", "ESP32 получает питание только от выхода ключа, не от GPIO Pico"),
    ("phase_signal_is_3v3", "ESP32 GPIO4 → резистор 1 кОм → Pico GP14; GP14 → 4,7 кОм → GND; сигнал 3,3 В, не 5 В"),
    ("adc_is_target_3v3_rail_via_divider", "ADC GP26 подключён к середине делителя: 3V3 ESP32 → 1 кОм → GP26 → 1 кОм → GND, не к 5 В"),
    ("adc_input_never_exceeds_3v3", "Делитель и щупы проверены: при включённой ESP32 GP26 около 1,65 В, всегда ниже 3,3 В"),
)


def configure(args):
    fresh(args.output)
    cfg = read(args.config)
    cal = read(args.calibration)
    if cfg.get("enabled") is not False or cal.get("schema") != "bench045_adc_calibration_v1" or cal.get("config_sha256") != sha(args.config):
        raise ValueError("Нужны исходная disabled-конфигурация и соответствующая ей калибровка")
    expected = fit_calibration(cal["off"], cal["on"], cal["off_voltage"], cal["on_voltage"])
    for key, value in expected.items():
        if not math.isclose(cal.get(key, float("nan")), value, rel_tol=1e-12, abs_tol=1e-12):
            raise ValueError("Файл калибровки изменён или повреждён")
    for key, prompt in CHECKS:
        ask_yes(prompt)
        cfg[key] = True
    transcript = args.output.with_name(args.output.stem + "-verification-serial.jsonl")
    with Link(args.port, transcript) as link:
        ident = identity(link, args.config)
        link.request("DISARM", "disarmed")
        ask_yes("Стенд подключён полностью, питание входа ключа и USB UART включены, Pico включён; ESP32 должна оставаться OFF")
        on_pin_off_v = ask_voltage("Измерьте мультиметром EN/ON ключа относительно GND при DISARM", 0, .30)
        off_v = ask_voltage("Измерьте мультиметром 3V3 ESP32 при DISARM (проверка паразитного питания)", 0, .1)
        off_adc = samples(link)
        inferred_off = expected["adc_zero_volts"] + expected["adc_volts_per_count"] * off_adc["mean"]
        if inferred_off > .15 or inferred_off < -.1:
            raise ValueError("ADC при DISARM не подтверждает выключенную плату; проверьте паразитное питание")
    cfg.update(expected)
    cfg.update(enabled=True, active_high_enable=True, adc_calibration_verified=True,
               external_switch_model="TPS22919EVM", phase_timing_verified=False,
               switch_to_rail_collapse_upper_us=None, phase_timing_evidence_file=None,
               phase_timing_evidence_sha256=None, bench045_calibration_sha256=sha(args.calibration),
               bench045_off_dmm_volts=off_v, bench045_on_pin_off_dmm_volts=on_pin_off_v, bench045_off_adc=off_adc,
               verification_notes="TPS22919EVM; operator-confirmed native USB D+/D- passthrough with VBUS switched through TPS22919EVM; external EN 2.2 kohm and phase 4.7 kohm pulldowns; phase 1 kohm series; target 3V3 via 1 kohm + 1 kohm divider; two-point DMM ADC calibration. No oscilloscope: supply collapse is not localized within the flash operation.")
    runner = load_runner(args.kit or cfg.get("bench045_kit"))
    runner.validate_wiring(cfg, require_phase_timing=False)
    save(args.output, cfg)
    return dict(status="reviewed_configuration_written", output=str(args.output), sha256=sha(args.output),
                physical_cut_tested=False, phase_timing_verified=False,
                next="Copy exact file to Pico as powercut_config.json and reboot; then run probe")


def probe(args):
    cfg = read(args.config)
    runner = load_runner(args.kit or cfg.get("bench045_kit"))
    runner.validate_wiring(cfg, config_path=args.config, require_phase_timing=False)
    args.output.mkdir(parents=True, exist_ok=False)
    result = dict(schema="bench045_probe_v1", original_author=AUTHOR, status="failed", hardware_access_attempted=True,
                  config_sha256=sha(args.config), phase_timing_verified=False)
    with Link(args.port, args.output / "serial.jsonl") as link:
        try:
            result["controller"] = identity(link, args.config)
            link.request("ARM PHYSICAL", "armed")
            time.sleep(2)
            before = samples(link)
            result["on_before"] = before
            before_v = cfg["adc_zero_volts"] + before["mean"] * cfg["adc_volts_per_count"]
            if before_v < cfg["rail_on_min_volts"] or before_v > 3.6:
                raise ValueError("После ARM нет ожидаемых 3,0…3,6 В на 3V3 ESP32")
            event = link.request("PROBE 2000", "probe_result", timeout=10)
            result["probe"] = event
            result["rail_evidence"] = runner.rail_evidence(event, cfg)
            if not result["rail_evidence"]["rail_off_confirmed"]:
                raise ValueError("Питание не остаётся ниже порога: проверьте обходное питание/делитель")
            time.sleep(2)
            after = samples(link)
            result["on_after"] = after
            after_v = cfg["adc_zero_volts"] + after["mean"] * cfg["adc_volts_per_count"]
            if not cfg["rail_on_min_volts"] <= after_v <= 3.6:
                raise ValueError("Питание ESP32 не восстановилось после PROBE")
            result.update(status="complete", on_before_volts=before_v, on_after_volts=after_v,
                          physical_supply_off_observed=True)
        except Exception as exc:
            result["error"] = str(exc)
            raise
        finally:
            try:
                result["disarm"] = link.request("DISARM", "disarmed")
            except Exception as exc:
                result["disarm_error"] = str(exc)
                result["status"] = "failed"
            result["finished_utc_ns"] = time.time_ns()
            save(args.output / "summary.json", result)
    if result["status"] != "complete":
        raise RuntimeError("DISARM не подтверждён: отключите входное питание стенда; см. summary.json")
    return dict(status="complete", output=str(args.output), power_at_end="OFF", phase_timing_verified=False)


def pack(args):
    root = args.run.resolve()
    target = fresh(args.output).resolve()
    fresh(target.with_name(target.name + ".sha256"))
    if not root.is_dir() or target.is_relative_to(root):
        raise ValueError("--run должна быть существующей папкой; архив сохраняйте вне неё")
    files = sorted(root.rglob("*"))
    if any(p.is_symlink() for p in files):
        raise ValueError("Символьные ссылки не архивируем; нужны исходные файлы")
    entries = [(p, "run/" + p.relative_to(root).as_posix()) for p in files if p.is_file()]
    entries.append((Path(__file__).resolve(), "tool/bench045.py"))
    partial = fresh(target.with_name(target.name + ".partial"))
    manifest = []
    with zipfile.ZipFile(partial, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for path, name in entries:
            before = path.stat()
            h = hashlib.sha256()
            with path.open("rb") as src, z.open(name, "w", force_zip64=True) as dst:
                for data in iter(lambda: src.read(1024 * 1024), b""):
                    dst.write(data)
                    h.update(data)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise RuntimeError("Файл изменился во время архивации; остановите запись: " + str(path))
            manifest.append(dict(path=name, bytes=after.st_size, sha256=h.hexdigest()))
        z.writestr("MANIFEST045.json", json.dumps(dict(schema="bench045_archive_v1", original_author=AUTHOR,
                   source=str(root), created_utc_ns=time.time_ns(), files=manifest), ensure_ascii=False, indent=2))
        z.writestr("README.txt", "Physical-cut setup and results archive. Original software: Oleksandr Kuznetsov.\n"
                   "run/ preserves every source file. MANIFEST045.json hashes archived bytes.\n"
                   "Read per-step summaries: packaging does not certify experiment completion.\n"
                   "Without independent timing evidence, phase_timing_verified remains false.\n")
    if target.exists():
        raise FileExistsError(target)
    partial.rename(target)
    digest = sha(target)
    with fresh(target.with_name(target.name + ".sha256")).open("x", encoding="ascii") as f:
        f.write(digest + "  " + target.name + "\n")
    return dict(status="archived", archive=str(target), bytes=target.stat().st_size, files=len(manifest), sha256=digest)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    q = sub.add_parser("init"); q.add_argument("--kit", type=Path, required=True); q.add_argument("--output", type=Path, required=True)
    q = sub.add_parser("identify"); q.add_argument("--port", required=True); q.add_argument("--output", type=Path)
    q = sub.add_parser("calibrate"); q.add_argument("--port", required=True); q.add_argument("--config", type=Path, required=True); q.add_argument("--output", type=Path, required=True)
    q = sub.add_parser("configure"); q.add_argument("--port", required=True); q.add_argument("--config", type=Path, required=True); q.add_argument("--calibration", type=Path, required=True); q.add_argument("--output", type=Path, required=True); q.add_argument("--kit", type=Path)
    q = sub.add_parser("probe"); q.add_argument("--port", required=True); q.add_argument("--config", type=Path, required=True); q.add_argument("--output", type=Path, required=True); q.add_argument("--kit", type=Path)
    q = sub.add_parser("pack"); q.add_argument("--run", type=Path, required=True); q.add_argument("--output", type=Path, required=True)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result = globals()[args.command](args)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        print("error: " + (str(exc) or "Прервано пользователем"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
