"""Связующий слой между ядром и интерфейсом: потоки, сигналы, таймеры."""
from __future__ import annotations

import os
import threading
import time

from PySide6.QtCore import QObject, QTimer, Signal

from timav import __version__
from timav.core import downloads, paths
from timav.core.clamav import ClamAVEngine, ScanVerdict, db_age_hours
from timav.core.devices import UsbWatcher
from timav.core.journal import Journal
from timav.core.monitor import RealtimeMonitor
from timav.core.process_guard import ProcessGuard
from timav.core.quarantine import Quarantine
from timav.core.ransomware import RansomwareGuard
from timav.core.scanner import Detection, Scanner, ScanStats
from timav.core.settings import Settings
from timav.core.system_status import DefenderStatus, SecurityScore, compute_score, query_defender
from timav.core.updater import update_databases
from timav.i18n import tr


def kind_ru(mode: str) -> str:
    return {"quick": tr("Быстрое"), "full": tr("Полное"), "custom": tr("Выборочное")}.get(mode, mode)


class Controller(QObject):
    engine_state = Signal(str)                  # loading | ready | fallback | missing | nodb
    scan_started = Signal(str)
    scan_progress = Signal(object)              # ScanStats
    scan_detection = Signal(object)             # Detection
    scan_finished = Signal(object)              # ScanStats
    realtime_threat = Signal(str, str, str, float, str)
    realtime_state = Signal(bool)
    protection_changed = Signal()
    ransom_alert = Signal(str, object)          # reason, suspect dict
    update_line = Signal(str)
    update_finished = Signal(bool, str)
    app_update = Signal(object)                 # selfupdate.Release | None | str(error)
    journal_changed = Signal()
    quarantine_changed = Signal()
    security_changed = Signal(object)
    defender_changed = Signal(object)
    notify = Signal(str, str, str)              # title, text, level
    _run_queue = Signal(list)
    _update_tick_signal = Signal()

    def __init__(self, settings: Settings):
        super().__init__()
        self._run_queue.connect(lambda q: self.start_scan("custom", q))
        self.settings = settings
        self.engine = ClamAVEngine(max_file_mb=settings.max_file_size_mb, scan_archives=settings.scan_archives)
        self.journal = Journal()
        self.journal.listeners.append(lambda _id: self.journal_changed.emit())
        self.quarantine = Quarantine()
        self.monitor: RealtimeMonitor | None = None
        self.pguard: ProcessGuard | None = None
        self.rguard: RansomwareGuard | None = None
        self.usb = UsbWatcher(self._on_usb)
        self.scanner: Scanner | None = None
        self.scan_thread: threading.Thread | None = None
        self.scan_queue: list[str] = []
        self.last_stats: ScanStats | None = None
        self.updating = False
        self.defender: DefenderStatus | None = None
        self.state = "loading"
        self._stop = threading.Event()
        self._prot_lock = threading.RLock()
        self._notified_downloads: dict[str, float] = {}
        self._update_tick_signal.connect(self._auto_update_tick)

        self._update_timer = QTimer(self)
        self._update_timer.timeout.connect(self._auto_update_tick)
        self._update_timer.start(10 * 60 * 1000)
        self._score_timer = QTimer(self)
        self._score_timer.timeout.connect(self.refresh_security)
        self._score_timer.start(60 * 1000)
        self._def_timer = QTimer(self)
        self._def_timer.timeout.connect(self.refresh_defender)
        self._def_timer.start(10 * 60 * 1000)

    # ---------- запуск ----------
    def startup(self):
        threading.Thread(target=self._boot, daemon=True).start()
        self.refresh_defender()
        self.sync_context_menu()
        if self.settings.check_app_updates and self.settings.update_feed_url and \
                time.time() - self.settings.last_app_update_check > 86400:
            QTimer.singleShot(30000, lambda: self.check_app_update(silent=True))

    def _boot(self):
        if not self.engine.available:
            self._set_state("missing")
            return
        if not self.engine.db_ready():
            self._set_state("nodb")
            self.journal.add("info", "info", "system", details=tr("Антивирусные базы отсутствуют — запускаю загрузку"))
            self.start_update()
            return
        self._start_engine()

    def _start_engine(self):
        if self.settings.use_daemon:
            self._set_state("loading")
            ok = self.engine.start_daemon(stop=self._stop)
            self._set_state("ready" if ok else "fallback")
        else:
            self._set_state("fallback")
        with self._prot_lock:
            if self.settings.realtime_enabled:
                self._set_realtime_locked(True)
            self._apply_protection_locked()
        self._update_tick_signal.emit()

    def _set_state(self, s: str):
        self.state = s
        self.engine_state.emit(s)
        self.refresh_security()

    def shutdown(self):
        self._stop.set()
        if self.scanner:
            self.scanner.cancel()
        for comp in (self.monitor, self.pguard, self.rguard):
            if comp:
                comp.stop()
        self.usb.stop()
        self.engine.stop_daemon()
        self.journal.close()

    def trusted_check(self, exe: str) -> bool:
        from timav.core.signer import is_trusted, signature
        valid, signer = signature(exe)
        return valid and is_trusted(signer, self.settings.trusted_publishers)

    # ---------- защита в реальном времени ----------
    def set_realtime(self, on: bool):
        """Переключение выполняется в фоне: остановка наблюдателя ФС может занимать секунды."""
        self.settings.realtime_enabled = on
        self.settings.save()
        threading.Thread(target=self._set_realtime_impl, args=(on,), daemon=True).start()

    def _set_realtime_impl(self, on: bool):
        with self._prot_lock:
            self._set_realtime_locked(on)

    def _set_realtime_locked(self, on: bool):
        if self.monitor:
            self.monitor.stop()
            self.monitor = None
        if on:
            if not self.engine.db_ready():
                self.realtime_state.emit(False)
                return
            folders = list(self.settings.watch_folders)
            dl = str(paths.user_folder("Downloads"))
            if self.settings.downloads_guard and dl not in folders and os.path.isdir(dl):
                folders.append(dl)
            self.monitor = RealtimeMonitor(self.engine, self._on_rt_threat, on_scanned=self._on_rt_scanned,
                                           heuristics=self.settings.heuristics_enabled,
                                           threshold=self.settings.heuristic_threshold,
                                           excluded=[str(paths.data_dir())] + self.settings.excluded_paths,
                                           trusted=self.settings.trusted_publishers)
            started = self.monitor.start(folders)
            self.journal.add("info", "info", "realtime", details=tr("Мониторинг включён: ") + "; ".join(started))
        else:
            self.journal.add("info", "low", "realtime", details=tr("Мониторинг в реальном времени выключен"))
        self.realtime_state.emit(on)
        self.refresh_security()

    def restart_realtime(self):
        if self.settings.realtime_enabled:
            self.set_realtime(True)

    def apply_protection(self):
        """Запуск/остановка контроля процессов, защиты от шифровальщиков и USB (в фоне)."""
        threading.Thread(target=self._apply_protection_impl, daemon=True).start()

    def _apply_protection_impl(self):
        with self._prot_lock:
            self._apply_protection_locked()

    def _apply_protection_locked(self):
        s = self.settings
        if s.process_guard and self.engine.db_ready():
            if not self.pguard:
                self.pguard = ProcessGuard(self.engine, self._on_process_event, s.heuristics_enabled,
                                           s.heuristic_threshold, s.trusted_publishers)
                self.pguard.start()
        elif self.pguard:
            self.pguard.stop()
            self.pguard = None
        if s.ransomware_guard:
            if self.rguard:
                self.rguard.stop()
            self.rguard = RansomwareGuard(s.protected_folders, self._on_ransom, self.trusted_check)
            self.rguard.start()
        elif self.rguard:
            self.rguard.stop()
            self.rguard.remove_canaries()
            self.rguard = None
        if s.usb_autoscan:
            self.usb.start()
        else:
            self.usb.stop()
        self.protection_changed.emit()
        self.refresh_security()

    def _on_rt_threat(self, path: str, name: str, kind: str, score: float):
        action = self._handle_detection(path, name, kind, score, "realtime")
        self.realtime_threat.emit(path, name, kind, score, action)
        title = tr("Обнаружена угроза") if kind == "threat" else tr("Подозрительный файл")
        self.notify.emit(title, f"{name}\n{os.path.basename(path)} — {action}", "danger" if kind == "threat" else "warning")
        self.refresh_security()

    def _on_rt_scanned(self, v: ScanVerdict):
        if not (self.settings.downloads_guard and v.status == "clean" and downloads.is_download(v.path)
                and downloads.worth_reporting(v.path)):
            return
        try:
            mtime = os.path.getmtime(v.path)
        except OSError:
            return
        key = os.path.normcase(v.path)
        if self._notified_downloads.get(key) == mtime:
            return          # этот файл уже проверялся и о нём уже сообщали
        self._notified_downloads[key] = mtime
        if len(self._notified_downloads) > 2000:
            self._notified_downloads.clear()
        info = downloads.zone_info(v.path)
        src = downloads.describe_source(info)
        self.journal.add("info", "info", "realtime", v.path, "", tr("загрузка проверена"),
                         tr("Угроз не найдено") + (f"; {src}" if src else ""))
        self.notify.emit(tr("Загрузка проверена"), f"{os.path.basename(v.path)} — {tr('угроз не найдено')}"
                         + (f"\n{src}" if src else ""), "good")

    def _on_process_event(self, kind: str, exe: str, name: str, pid: int, action: str):
        sev = "high" if kind == "threat" else "medium"
        if kind == "threat":
            try:
                self.quarantine.add(exe, name)
                action += tr(", файл в карантине")
                self.quarantine_changed.emit()
            except OSError:
                pass
        self.journal.add(kind, sev, "process", exe, name, action, f"PID {pid}")
        title = tr("Заблокирован запуск угрозы") if kind == "threat" else tr("Запущена подозрительная программа")
        self.notify.emit(title, f"{os.path.basename(exe)} — {name}\n{action}", "danger" if kind == "threat" else "warning")
        self.refresh_security()

    def _on_ransom(self, reason: str, suspect: dict | None):
        details = reason
        if suspect:
            details += f"; {tr('процесс')}: {suspect['name']} (PID {suspect['pid']})"
            if suspect.get("suspended"):
                details += tr(" — приостановлен")
        self.journal.add("threat", "high", "ransomware", suspect["exe"] if suspect else "", tr("Поведение шифровальщика"),
                         tr("процесс приостановлен") if suspect and suspect.get("suspended") else tr("обнаружено"), details)
        self.notify.emit(tr("Признаки шифровальщика!"), details, "danger")
        self.ransom_alert.emit(reason, suspect)
        self.refresh_security()

    def resolve_ransom(self, suspect: dict, kill: bool):
        if not self.rguard:
            return
        ok = self.rguard.resolve(suspect["pid"], kill)
        if kill and ok and suspect.get("exe") and os.path.isfile(suspect["exe"]):
            try:
                self.quarantine.add(suspect["exe"], tr("Поведение шифровальщика"))
                self.quarantine_changed.emit()
            except OSError:
                pass
        self.journal.add("info", "info", "ransomware", suspect.get("exe", ""), "",
                         tr("процесс завершён") if kill else tr("процесс возобновлён"))

    def _on_usb(self, root: str, label: str):
        self.journal.add("info", "info", "usb", root, "", tr("подключён носитель"), label)
        self.notify.emit(tr("Подключён съёмный носитель"), f"{label or root} — {tr('запускаю проверку')}", "info")
        self._run_queue.emit([root])

    def _handle_detection(self, path: str, name: str, kind: str, score: float, source: str) -> str:
        action = tr("обнаружено")
        if kind == "threat" and self.settings.auto_quarantine:
            try:
                self.quarantine.add(path, name)
                action = tr("в карантине")
                self.quarantine_changed.emit()
            except OSError as e:
                action = tr("ошибка")
                name = f"{name} ({tr('не удалось изолировать')}: {e.strerror})"
        sev = "high" if kind == "threat" else "medium"
        details = tr("AI-оценка риска: {p}", p=f"{score:.0%}") if kind == "suspicious" else ""
        self.journal.add(kind, sev, source, path, name, action, details)
        return action

    # ---------- сканирование ----------
    @property
    def scanning(self) -> bool:
        return self.scan_thread is not None and self.scan_thread.is_alive()

    def start_scan(self, mode: str, custom: list[str] | None = None) -> bool:
        if not self.engine.available:
            return False
        if self.scanning:
            if mode == "custom" and custom:
                self.scan_queue.extend(custom)   # проверим после текущего сканирования
                self.notify.emit(tr("Добавлено в очередь"), "\n".join(os.path.basename(c) or c for c in custom), "info")
            return False
        if not self.engine.db_ready():
            self.notify.emit(tr("Нет антивирусных баз"), tr("Дождитесь завершения обновления баз"), "warning")
            return False
        s = self.settings
        self.scanner = Scanner(self.engine, s.heuristics_enabled, s.heuristic_threshold, s.excluded_paths,
                               trusted=s.trusted_publishers)
        self.journal.add("scan", "info", "scan", details=tr("{k} сканирование запущено", k=kind_ru(mode)))
        self.scan_thread = threading.Thread(target=self._scan_run, args=(mode, custom), daemon=True)
        self.scan_thread.start()
        self.scan_started.emit(mode)
        return True

    def _scan_run(self, mode, custom):
        def on_det(d: Detection):
            d.action = tr("обнаружено")
            sev = "high" if d.kind == "threat" else "medium"
            details = tr("AI-оценка риска: {p}", p=f"{d.score:.0%}") if d.kind == "suspicious" else ""
            d.event_id = self.journal.add(d.kind, sev, "scan", d.path, d.name, d.action, details)
            self.scan_detection.emit(d)

        stats: ScanStats = self.scanner.run(mode, custom, on_progress=self.scan_progress.emit, on_detection=on_det)
        self.last_stats = stats
        self.settings.last_scan_ts = time.time()
        self.settings.last_scan_kind = mode
        self.settings.save()
        threats = sum(1 for d in stats.detections if d.kind == "threat")
        susp = len(stats.detections) - threats
        status = tr("прервано") if stats.cancelled else tr("завершено")
        self.journal.add("scan", "info", "scan",
                         details=tr("{k} сканирование {s}: проверено {n}, угроз {t}, подозрительных {u}, время {sec} с",
                                    k=kind_ru(mode), s=status, n=stats.scanned, t=threats, u=susp, sec=int(stats.elapsed)))
        self.scan_finished.emit(stats)
        if threats or susp:
            self.notify.emit(tr("Сканирование завершено"), tr("Найдено угроз: {t}, подозрительных: {u}", t=threats, u=susp), "danger")
        else:
            self.notify.emit(tr("Сканирование завершено"), tr("Угроз не найдено. Проверено файлов: {n}", n=stats.scanned), "good")
        self.refresh_security()
        if self.scan_queue:
            q, self.scan_queue = self.scan_queue, []
            self._run_queue.emit(q)   # запуск из главного потока

    def cancel_scan(self):
        if self.scanner:
            self.scanner.cancel()

    def pause_scan(self, paused: bool):
        if self.scanner:
            self.scanner.pause(paused)

    def resolve_detection(self, d: Detection, action: str) -> str:
        try:
            if action == "quarantine":
                self.quarantine.add(d.path, d.name)
                d.action = tr("в карантине")
                self.quarantine_changed.emit()
            elif action == "delete":
                os.remove(d.path)
                d.action = tr("удалено")
            else:
                d.action = tr("пропущено")
        except OSError as e:
            d.action = tr("ошибка")
            self.notify.emit(tr("Не удалось выполнить действие"), f"{os.path.basename(d.path)}: {e.strerror}", "warning")
        if d.event_id:
            self.journal.update_action(d.event_id, d.action)
            self.journal_changed.emit()
        self.refresh_security()
        return d.action

    # ---------- обновление баз ----------
    def _auto_update_tick(self):
        s = self.settings
        if not s.auto_update or self.updating or not self.engine.available:
            return
        if time.time() - s.last_update_ts >= s.update_interval_hours * 3600:
            self.start_update()

    def start_update(self):
        if self.updating or not self.engine.available:
            return
        self.updating = True
        threading.Thread(target=self._update_run, daemon=True).start()

    def _update_run(self):
        had_db = self.engine.db_ready()
        res = update_databases(self.engine, on_line=self.update_line.emit)
        self.updating = False
        if res.ok:
            self.settings.last_update_ts = time.time()
            self.settings.save()
        self.journal.add("update", "info" if res.ok else "low", "updater", details=tr(res.message))
        self.update_finished.emit(res.ok, tr(res.message))
        if res.ok and not had_db and self.engine.db_ready():
            self._start_engine()
        self.refresh_security()

    # ---------- обновление программы ----------
    def check_app_update(self, silent: bool = False):
        def run():
            from timav.core import selfupdate
            try:
                rel = selfupdate.check(self.settings.update_feed_url, __version__)
                self.settings.last_app_update_check = time.time()
                self.settings.save()
                self.app_update.emit(rel)
                if rel and silent:
                    self.notify.emit(tr("Доступна новая версия"), f"Tim Antivirus {rel.version}", "info")
            except Exception as e:  # noqa: BLE001
                if not silent:
                    self.app_update.emit(str(e))
        threading.Thread(target=run, daemon=True).start()

    # ---------- интеграции ----------
    def sync_context_menu(self):
        from timav.core import shell
        try:
            if self.settings.context_menu:
                shell.register(tr("Проверить в Tim Antivirus"))
            else:
                shell.unregister()
        except OSError:
            pass

    # ---------- безопасность ----------
    def refresh_defender(self):
        def run():
            self.defender = query_defender()
            self.defender_changed.emit(self.defender)
            self.refresh_security()
        threading.Thread(target=run, daemon=True).start()

    def security(self) -> SecurityScore:
        return compute_score(
            engine_ok=self.engine.available,
            db_age_hours=db_age_hours(self.engine) if self.engine.db_ready() else None,
            realtime=bool(self.monitor and self.monitor.running),
            unresolved=self.journal.unresolved_threats(),
            last_scan_ts=self.settings.last_scan_ts,
            defender=self.defender,
        )

    def refresh_security(self):
        try:
            self.security_changed.emit(self.security())
        except Exception:
            pass
