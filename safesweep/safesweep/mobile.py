"""SafeSweep phone app (Kivy). Same engine as the desktop app, touch-friendly UI.

Runs on Android (built with Buildozer) and, for development, on any desktop
with `pip install kivy` and `python main.py`.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from .config import android_shared_storage, is_android_app

APP_VERSION = __import__("safesweep").__version__


# --------------------------------------------------------------------------- Android glue
def _sdk_int() -> int:
    from jnius import autoclass  # type: ignore
    return autoclass("android.os.Build$VERSION").SDK_INT


def has_storage_access() -> bool:
    if not is_android_app():
        return True
    try:
        if _sdk_int() >= 30:
            from jnius import autoclass  # type: ignore
            return bool(autoclass("android.os.Environment").isExternalStorageManager())
        from android.permissions import Permission, check_permission  # type: ignore
        return check_permission(Permission.WRITE_EXTERNAL_STORAGE)
    except Exception:
        return False


def request_storage_access() -> None:
    if not is_android_app():
        return
    from jnius import autoclass  # type: ignore
    if _sdk_int() >= 30:
        Intent = autoclass("android.content.Intent")
        Settings = autoclass("android.provider.Settings")
        Uri = autoclass("android.net.Uri")
        activity = autoclass("org.kivy.android.PythonActivity").mActivity
        try:
            intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
            intent.setData(Uri.parse("package:" + activity.getPackageName()))
            activity.startActivity(intent)
        except Exception:
            activity.startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
    else:
        from android.permissions import Permission, request_permissions  # type: ignore
        request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])


def _android_intent_extra(name: str) -> str | None:
    try:
        from jnius import autoclass  # type: ignore
        intent = autoclass("org.kivy.android.PythonActivity").mActivity.getIntent()
        return intent.getStringExtra(name) if intent else None
    except Exception:
        return None


def prepare_environment() -> None:
    """Point SafeSweep's data folder and temp dir at sensible places for this device."""
    if is_android_app():
        try:  # temp files go to the app's cache folder (never the program folder)
            from jnius import autoclass  # type: ignore
            cache = autoclass("org.kivy.android.PythonActivity").mActivity.getCacheDir().getAbsolutePath()
            os.environ["TMPDIR"] = cache
            import tempfile
            tempfile.tempdir = cache
        except Exception:
            pass


def use_shared_home() -> None:
    """On Android keep the Review folder on phone storage so you can see it in a file manager."""
    if not is_android_app() or os.environ.get("SAFESWEEP_HOME"):
        return
    shared = android_shared_storage()
    if shared:
        home = shared / "SafeSweep"
        try:
            home.mkdir(parents=True, exist_ok=True)
            (home / ".nomedia").touch()  # keep reviewed photos out of the gallery
            os.environ["SAFESWEEP_HOME"] = str(home)
        except OSError:
            pass


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# --------------------------------------------------------------------------- UI
KV = r"""
#:import dp kivy.metrics.dp
#:set TEAL (0.05, 0.55, 0.50, 1)
#:set INK (0.12, 0.13, 0.15, 1)
#:set MUTED (0.42, 0.44, 0.48, 1)
#:set BG (0.97, 0.97, 0.98, 1)

<Ink@Label>:
    color: INK
    text_size: self.width, None
    size_hint_y: None
    height: self.texture_size[1]
    halign: 'left'
    valign: 'middle'
    markup: True

<Muted@Ink>:
    color: MUTED
    font_size: '13sp'

<Accent@Button>:
    background_normal: ''
    background_down: ''
    background_color: TEAL if self.state == 'normal' else (0.03, 0.40, 0.36, 1)
    color: 1, 1, 1, 1
    bold: True
    font_size: '15sp'
    size_hint_y: None
    height: dp(48)

<Plain@Button>:
    background_normal: ''
    background_down: ''
    background_color: (0.90, 0.92, 0.93, 1) if self.state == 'normal' else (0.80, 0.83, 0.85, 1)
    color: INK
    font_size: '14sp'
    size_hint_y: None
    height: dp(48)

<Danger@Button>:
    background_normal: ''
    background_down: ''
    background_color: (0.75, 0.15, 0.15, 1) if self.state == 'normal' else (0.55, 0.1, 0.1, 1)
    color: 1, 1, 1, 1
    bold: True
    font_size: '14sp'
    size_hint_y: None
    height: dp(48)

<TabButton@ToggleButton>:
    group: 'tabs'
    allow_no_selection: False
    background_normal: ''
    background_down: ''
    background_color: (1, 1, 1, 1)
    color: TEAL if self.state == 'down' else MUTED
    bold: self.state == 'down'
    font_size: '15sp'

<ItemRow>:
    size_hint_y: None
    height: max(dp(76), box.minimum_height + dp(16))
    padding: dp(6), dp(8), dp(12), dp(8)
    spacing: dp(6)
    canvas.before:
        Color:
            rgba: (0.90, 0.97, 0.95, 1) if root.selected else (1, 1, 1, 1)
        Rectangle:
            pos: self.pos
            size: self.size
        Color:
            rgba: (0.75, 0.10, 0.12, 1) if root.severity == 'high' else ((0.85, 0.55, 0.05, 1) if root.severity == 'medium' else (0, 0, 0, 0))
        Rectangle:
            pos: self.x, self.y
            size: dp(4), self.height
        Color:
            rgba: 0.88, 0.89, 0.90, 1
        Rectangle:
            pos: self.x, self.y
            size: self.width, dp(1)
    CheckBox:
        size_hint: None, None
        size: dp(44), dp(44)
        pos_hint: {'center_y': .5}
        active: root.selected
        color: (0.05, 0.55, 0.50, 1)
        on_active: root.toggled(self.active)
    BoxLayout:
        id: box
        orientation: 'vertical'
        size_hint_y: None
        height: self.minimum_height
        pos_hint: {'center_y': .5}
        spacing: dp(2)
        BoxLayout:
            size_hint_y: None
            height: title.height
            Ink:
                id: title
                text: '[b]' + root.title + '[/b]'
                font_size: '15sp'
                shorten: True
                shorten_from: 'center'
            Label:
                size_hint: None, None
                size: self.texture_size[0] + dp(4), title.height
                text: root.size_text
                color: MUTED
                font_size: '13sp'
        Ink:
            text: ('[color=0d8c7f][b]Recommended[/b][/color]  ' if root.recommended else '') + root.reason
            font_size: '13sp'
        Muted:
            text: root.detail
            font_size: '12sp'
            shorten: True
            shorten_from: 'center'
            max_lines: 1

<ItemList@RecycleView>:
    viewclass: 'ItemRow'
    bar_width: dp(4)
    RecycleBoxLayout:
        default_size: None, dp(76)
        default_size_hint: 1, None
        size_hint_y: None
        height: self.minimum_height
        orientation: 'vertical'

<FindingsScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: dp(12), dp(10)
        spacing: dp(8)
        Muted:
            text: root.intro
        BoxLayout:
            size_hint_y: None
            height: dp(40) if root.is_scan else 0
            opacity: 1 if root.is_scan else 0
            disabled: not root.is_scan
            spacing: dp(8)
            Label:
                text: root.feed_status
                color: (0.04, 0.43, 0.39, 1)
                font_size: '12sp'
                text_size: self.size
                halign: 'left'
                valign: 'middle'
            Plain:
                text: 'Update lists'
                size_hint: None, None
                size: dp(110), dp(40)
                font_size: '13sp'
                disabled: root.running
                on_release: root.update_lists()
        BoxLayout:
            size_hint_y: None
            height: dp(48)
            spacing: dp(8)
            Spinner:
                id: where
                text: root.where_choices[0] if root.where_choices else ''
                values: root.where_choices
                background_normal: ''
                background_color: (0.90, 0.92, 0.93, 1)
                color: INK
                font_size: '14sp'
            Accent:
                text: 'Stop' if root.running else 'Start'
                size_hint_x: None
                width: dp(110)
                on_release: root.stop() if root.running else root.start()
        Ink:
            text: root.summary
            font_size: '14sp'
        ProgressBar:
            size_hint_y: None
            height: dp(4) if root.running else 0
            opacity: 1 if root.running else 0
            max: 100
            value: root.pulse
        ItemList:
            id: rv
            canvas.before:
                Color:
                    rgba: 1, 1, 1, 1
                Rectangle:
                    pos: self.pos
                    size: self.size
        BoxLayout:
            size_hint_y: None
            height: dp(48)
            spacing: dp(8)
            Plain:
                text: 'Recommended'
                on_release: root.select('recommended')
            Plain:
                text: 'None'
                size_hint_x: .6
                on_release: root.select('none')
            Accent:
                text: 'Move %d to Review' % root.selected_count
                disabled: root.selected_count == 0 or root.running
                on_release: root.move_selected()

<ReviewScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: dp(12), dp(10)
        spacing: dp(8)
        Muted:
            text: 'Files wait here until you decide. [b]Restore[/b] puts a file back exactly where it was. [b]Delete[/b] removes it for good. Folder: ' + root.folder
        Ink:
            text: root.summary
            font_size: '14sp'
        ItemList:
            id: rv
            canvas.before:
                Color:
                    rgba: 1, 1, 1, 1
                Rectangle:
                    pos: self.pos
                    size: self.size
        BoxLayout:
            size_hint_y: None
            height: dp(48)
            spacing: dp(8)
            Plain:
                text: 'All'
                size_hint_x: .5
                on_release: root.select('all')
            Plain:
                text: 'Restore'
                disabled: root.selected_count == 0
                on_release: root.restore_selected()
            Danger:
                text: 'Delete %d' % root.selected_count
                disabled: root.selected_count == 0
                on_release: root.delete_selected()
        Plain:
            text: 'Delete items older than %d days' % root.retention
            on_release: root.purge_expired()

<PermissionView>:
    orientation: 'vertical'
    padding: dp(24)
    spacing: dp(16)
    canvas.before:
        Color:
            rgba: BG
        Rectangle:
            pos: self.pos
            size: self.size
    Widget:
    Image:
        source: root.icon
        size_hint_y: None
        height: dp(120)
    Ink:
        text: '[b]Allow access to your files[/b]'
        font_size: '22sp'
        halign: 'center'
    Ink:
        text: "To scan for viruses and clean up junk, SafeSweep needs [b]All files access[/b]. On the next screen, switch on [b]Allow access to manage all files[/b], then come back.\n\nYour files never leave your phone. Nothing is deleted without your confirmation."
        font_size: '15sp'
        halign: 'center'
    Accent:
        text: 'Open settings'
        on_release: root.request()
    Plain:
        text: "I've allowed it"
        on_release: root.recheck()
    Widget:

<MainView>:
    orientation: 'vertical'
    canvas.before:
        Color:
            rgba: BG
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        size_hint_y: None
        height: dp(56)
        padding: dp(12), dp(6)
        spacing: dp(10)
        canvas.before:
            Color:
                rgba: TEAL
            Rectangle:
                pos: self.pos
                size: self.size
        Image:
            source: root.icon
            size_hint_x: None
            width: dp(36)
        Label:
            text: '[b]SafeSweep[/b]'
            markup: True
            font_size: '20sp'
            text_size: self.size
            halign: 'left'
            valign: 'middle'
        Button:
            text: 'Self-test'
            size_hint_x: None
            width: dp(96)
            background_normal: ''
            background_color: (1, 1, 1, 0.18)
            on_release: app.run_selftest()
    ScreenManager:
        id: sm
    BoxLayout:
        size_hint_y: None
        height: dp(56)
        canvas.before:
            Color:
                rgba: 0.86, 0.87, 0.88, 1
            Rectangle:
                pos: self.x, self.top - dp(1)
                size: self.width, dp(1)
        TabButton:
            text: 'Scan'
            state: 'down'
            on_press: sm.current = 'scan'
        TabButton:
            id: clean_tab
            text: 'Clean'
            on_press: sm.current = 'clean'
        TabButton:
            id: review_tab
            text: 'Review'
            on_press: sm.current = 'review'; app.review_screen.refresh()
    Label:
        size_hint_y: None
        height: dp(28)
        text: app.status
        color: MUTED
        font_size: '12sp'
        text_size: self.width - dp(16), None
        shorten: True
        canvas.before:
            Color:
                rgba: 1, 1, 1, 1
            Rectangle:
                pos: self.pos
                size: self.size
"""


def run() -> None:
    global app
    prepare_environment()
    from kivy.app import App
    from kivy.clock import Clock, mainthread
    from kivy.core.window import Window
    from kivy.lang import Builder
    from kivy.metrics import dp
    from kivy.properties import BooleanProperty, ListProperty, NumericProperty, StringProperty
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.button import Button
    from kivy.uix.label import Label
    from kivy.uix.popup import Popup
    from kivy.uix.recycleview.views import RecycleDataViewBehavior
    from kivy.uix.screenmanager import Screen
    from kivy.uix.scrollview import ScrollView

    if not is_android_app() and not os.environ.get("SAFESWEEP_KEEP_WINDOW"):
        Window.size = (420, 860)  # phone-sized window on desktop
    Window.clearcolor = (0.97, 0.97, 0.98, 1)

    here = Path(__file__).resolve().parent
    icon_path = next((str(p) for p in (here.parent / "assets" / "icon.png", here / "assets" / "icon.png")
                 if p.exists()), "")

    class ItemRow(RecycleDataViewBehavior, BoxLayout):
        title = StringProperty("")
        reason = StringProperty("")
        detail = StringProperty("")
        size_text = StringProperty("")
        severity = StringProperty("low")
        recommended = BooleanProperty(False)
        selected = BooleanProperty(False)
        index = NumericProperty(0)
        owner = None

        def refresh_view_attrs(self, rv, index, data):
            self.index = index
            self.owner = data.get("owner")
            return super().refresh_view_attrs(rv, index, data)

        def toggled(self, value):
            if self.owner is not None and self.selected != value:
                self.selected = value
                self.owner.set_selected(self.index, value)

    def popup(title, text, buttons=(("OK", None),), tall=False):
        box = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(10))
        sv = ScrollView()
        lbl = Label(text=text, markup=True, size_hint_y=None, halign="left", valign="top",
                    color=(1, 1, 1, 1), font_size="14sp")
        lbl.bind(width=lambda *_: setattr(lbl, "text_size", (lbl.width, None)),
                 texture_size=lambda *_: setattr(lbl, "height", lbl.texture_size[1]))
        sv.add_widget(lbl)
        box.add_widget(sv)
        row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))
        p = Popup(title=title, content=box, size_hint=(0.92, 0.8 if tall else 0.38), auto_dismiss=False)
        for label, fn in buttons:
            b = Button(text=label)
            b.bind(on_release=lambda _b, fn=fn: (p.dismiss(), fn and fn()))
            row.add_widget(b)
        box.add_widget(row)
        p.open()
        return p, lbl

    class Selectable:
        """Shared list-selection behaviour for the result and review screens."""
        selected_count = NumericProperty(0)

        def set_selected(self, index, value):
            data = self.ids.rv.data
            if 0 <= index < len(data):
                data[index]["selected"] = value
            self.selected_count = sum(1 for d in data if d["selected"])

        def _set_all(self, pred):
            for d in self.ids.rv.data:
                d["selected"] = bool(pred(d))
            self.ids.rv.refresh_from_data()
            self.selected_count = sum(1 for d in self.ids.rv.data if d["selected"])

    class FindingsScreen(Selectable, Screen):
        intro = StringProperty("")
        summary = StringProperty("")
        running = BooleanProperty(False)
        pulse = NumericProperty(0)
        where_choices = ListProperty([])
        is_scan = BooleanProperty(False)
        feed_status = StringProperty("")

        def setup(self, mode):
            self.mode = mode
            self.is_scan = mode == "scan"
            self.refresh_feed_status()
            self.findings = []
            self.cancel = threading.Event()
            self.where_map = app.locations(mode)
            self.where_choices = list(self.where_map)
            self.ids.where.text = self.where_choices[0]
            if mode == "scan":
                self.intro = ("Looks for known malware (lists updated daily from abuse.ch), apps and programs "
                              "disguised as photos or documents, fake file extensions and dangerous scripts.")
                self.summary = "Tap [b]Start[/b] to scan."
            else:
                self.intro = ("Finds temporary files, thumbnail caches, empty files, exact duplicate photos/videos "
                              "and old downloads. App data is never touched.")
                self.summary = "Tap [b]Start[/b] to look for junk."

        def start(self, overrides=None, done_cb=None):
            from .config import Settings
            from .junk import find_junk
            from .scanner import scan
            settings = Settings.load()
            settings.use_clamav = False
            for k, v in (overrides or {}).items():
                if hasattr(settings, k):
                    setattr(settings, k, v)
            paths = self.where_map.get(self.ids.where.text) or []
            if not paths:
                self.summary = "That folder isn't available on this device."
                return
            self.running = True
            self.cancel.clear()
            self.ids.rv.data = []
            self.selected_count = 0
            self.summary = "Working…"
            stats: dict = {}
            worker = scan if self.mode == "scan" else find_junk
            started = time.time()
            self._tick = Clock.schedule_interval(lambda dt: setattr(self, "pulse", (self.pulse + 4) % 100), 0.05)

            def job():
                try:
                    if self.mode == "scan" and settings.threat_feeds_enabled and not (overrides or {}).get("offline"):
                        from .feeds import maybe_update
                        try:
                            maybe_update(settings, app.set_status, cancelled=self.cancel.is_set)
                        except Exception:
                            pass  # never block a scan because the internet is down
                    res = worker(settings, paths, lambda p: app.set_status(f"Checking {p}"),
                                 self.cancel.is_set, stats=stats)
                    err = None
                except Exception as e:  # never crash the app
                    res, err = [], e
                self.finished(res, stats, err, time.time() - started, done_cb)

            threading.Thread(target=job, daemon=True).start()

        def stop(self):
            self.cancel.set()

        @mainthread
        def refresh_feed_status(self, *_):
            from .config import Settings
            from .feeds import status_text
            self.feed_status = status_text(Settings.load()).replace("Online threat lists: ", "Threat lists: ")

        def update_lists(self):
            from .config import Settings
            self.running = True
            app.set_status("Downloading threat lists from verified sources (abuse.ch)…")

            def job():
                from .feeds import update_all
                try:
                    lines = update_all(Settings.load(), app.set_status)
                except Exception as e:
                    lines = [f"Update failed: {e}"]
                self.lists_updated(lines)

            threading.Thread(target=job, daemon=True).start()

        @mainthread
        def lists_updated(self, lines):
            self.running = False
            self.refresh_feed_status()
            app.set_status(self.feed_status)
            popup("Threat lists", "\n\n".join(lines))

        @mainthread
        def finished(self, res, stats, err, secs, done_cb):
            self._tick.cancel()
            self.running = False
            if err:
                self.summary = f"[color=b00020]Error:[/color] {err}"
                app.set_status("Something went wrong - nothing was changed.")
                if done_cb:
                    done_cb(res, stats)
                return
            self.findings = res
            self.ids.rv.data = [{
                "title": os.path.basename(f.path), "reason": f.reason,
                "detail": os.path.dirname(f.path), "size_text": human(f.size),
                "severity": f.severity, "recommended": f.recommended,
                "selected": f.recommended, "owner": self} for f in res]
            self.selected_count = sum(1 for f in res if f.recommended)
            rec = [f for f in res if f.recommended]
            head = f"{stats.get('files', 0)} files checked in {secs:.0f}s. "
            if stats.get("cancelled"):
                head = "[b]Stopped early[/b] - results are incomplete. " + head
            if not res:
                self.summary = head + ("[b]No threats found.[/b]" if self.mode == "scan" else "[b]No junk found.[/b]")
            else:
                self.summary = (head + f"[b]{len(res)}[/b] found ({human(sum(f.size for f in res))}). "
                                f"[b]{len(rec)}[/b] recommended are ticked.")
            app.set_status("Done.")
            self.refresh_feed_status()
            if done_cb:
                done_cb(res, stats)

        def select(self, how):
            self._set_all(lambda d: how == "recommended" and d["recommended"])

        def move_selected(self, done_cb=None):
            picked = [(i, f) for i, (f, d) in enumerate(zip(self.findings, self.ids.rv.data)) if d["selected"]]
            unsure = sum(1 for _, f in picked if not f.recommended)

            def go():
                self.running = True
                app.set_status(f"Moving {len(picked)} item(s) to Review…")

                def job():
                    from .config import Settings
                    from .review import ReviewError, ReviewFolder
                    ok, errors = [], []
                    try:
                        rf = ReviewFolder(Settings.load())
                        for i, f in picked:
                            try:
                                rf.move_in(f)
                                ok.append(i)
                            except (ReviewError, OSError) as e:
                                errors.append(f"{os.path.basename(f.path)}: {e}")
                    except Exception as e:
                        errors.append(str(e))
                    self.moved(ok, errors, done_cb)

                threading.Thread(target=job, daemon=True).start()

            if unsure and done_cb is None:
                popup("Take a look first?",
                      f"{unsure} selected item(s) are not marked [b]Recommended[/b] - you may still want them.\n\n"
                      "They will only be moved to the Review folder, not deleted.",
                      (("Cancel", None), ("Move", go)))
            else:
                go()

        @mainthread
        def moved(self, ok, errors, done_cb):
            self.running = False
            keep = set(ok)
            self.findings = [f for i, f in enumerate(self.findings) if i not in keep]
            self.ids.rv.data = [d for i, d in enumerate(self.ids.rv.data) if i not in keep]
            self.selected_count = sum(1 for d in self.ids.rv.data if d["selected"])
            app.set_status(f"Moved {len(ok)} item(s) to Review. Nothing was deleted.")
            app.review_screen.refresh()
            if errors:
                popup(f"{len(errors)} item(s) left in place", "\n".join(errors[:20]), tall=True)
            if done_cb:
                done_cb(ok, errors)

    class ReviewScreen(Selectable, Screen):
        summary = StringProperty("")
        folder = StringProperty("")
        retention = NumericProperty(30)

        def refresh(self):
            from .config import Settings
            from .review import ReviewFolder
            try:
                settings = Settings.load()
                self.rf = ReviewFolder(settings)
            except Exception as e:
                self.summary = f"Review folder unavailable: {e}"
                return
            self.retention = settings.review_retention_days
            self.folder = str(self.rf.files)
            self.items = self.rf.items()
            self.ids.rv.data = [{
                "title": os.path.basename(it.original_path), "reason": it.reason,
                "detail": f"{it.age_days:.0f} days in review - from {os.path.dirname(it.original_path)}",
                "size_text": human(it.size), "severity": "high" if it.category == "threat" else "low",
                "recommended": False, "selected": False, "owner": self} for it in self.items]
            self.selected_count = 0
            total = sum(i.size for i in self.items)
            self.summary = (f"[b]{len(self.items)}[/b] item(s), {human(total)}." if self.items
                            else "The Review folder is empty.")

        def select(self, how):
            everything = all(d["selected"] for d in self.ids.rv.data)
            self._set_all(lambda d: not everything)

        def _picked(self):
            return [it for it, d in zip(self.items, self.ids.rv.data) if d["selected"]]

        def restore_selected(self):
            picked = self._picked()
            threats = [it for it in picked if it.category == "threat"]

            def go():
                errors = []
                for it in picked:
                    try:
                        self.rf.restore(it.id)
                    except Exception as e:
                        errors.append(f"{os.path.basename(it.original_path)}: {e}")
                self.refresh()
                app.set_status(f"Restored {len(picked) - len(errors)} item(s).")
                if errors:
                    popup("Some items could not be restored", "\n".join(errors[:20]))

            if threats:
                popup("Restore a flagged threat?",
                      f"{len(threats)} of these were flagged as threats, e.g.\n[b]{threats[0].reason}[/b]\n\nRestore anyway?",
                      (("Cancel", None), ("Restore", go)))
            else:
                go()

        def delete_selected(self):
            picked = self._picked()
            size = sum(i.size for i in picked)

            def go():
                freed = 0
                for it in picked:
                    try:
                        freed += self.rf.delete(it.id)
                    except Exception:
                        pass
                self.refresh()
                app.set_status(f"Deleted {len(picked)} item(s), freed {human(freed)}.")

            popup("Delete permanently?", f"Delete {len(picked)} item(s) ({human(size)}) for good?\n\nThis cannot be undone.",
                  (("Cancel", None), ("Delete", go)))

        def purge_expired(self):
            def go():
                n, freed = self.rf.purge(self.retention)
                self.refresh()
                app.set_status(f"Deleted {n} old item(s), freed {human(freed)}.")
            popup("Delete old items?", f"Permanently delete items that have been in review for {self.retention}+ days?",
                  (("Cancel", None), ("Delete", go)))

    class PermissionView(BoxLayout):
        icon = StringProperty(icon_path)

        def request(self):
            request_storage_access()

        def recheck(self):
            app.check_access()

    class MainView(BoxLayout):
        icon = StringProperty(icon_path)

    Builder.load_string(KV)

    class SafeSweepApp(App):
        status = StringProperty(f"SafeSweep {APP_VERSION}. Nothing is deleted without your confirmation.")
        title = "SafeSweep"

        def build(self):
            self.icon = icon_path
            self.root_box = BoxLayout()
            self.main = None
            self.check_access()
            return self.root_box

        def locations(self, mode):
            shared = android_shared_storage() if is_android_app() else None
            if shared:
                opts = {"Whole phone storage": [str(shared)],
                        "Downloads": [str(shared / "Download")],
                        "Photos & camera": [str(p) for p in (shared / "DCIM", shared / "Pictures") if p.exists()],
                        "WhatsApp & Telegram media": [str(p) for p in (
                            shared / "Android" / "media" / "com.whatsapp" / "WhatsApp" / "Media",
                            shared / "WhatsApp" / "Media", shared / "Telegram") if p.exists()]}
                return {k: v for k, v in opts.items() if v}
            from .config import Settings
            s = Settings.load()
            home = Path.home()
            opts = {"Default folders": s.scan_paths if mode == "scan" else s.junk_paths,
                    "Downloads": [str(home / "Downloads")], "Home folder": [str(home)]}
            return {k: [p for p in v if os.path.isdir(p)] for k, v in opts.items()}

        def check_access(self):
            self.root_box.clear_widgets()
            if has_storage_access():
                use_shared_home()
                if self.main is None:
                    self.main = MainView()
                    sm = self.main.ids.sm
                    self.scan_screen = FindingsScreen(name="scan")
                    self.clean_screen = FindingsScreen(name="clean")
                    self.review_screen = ReviewScreen(name="review")
                    for s in (self.scan_screen, self.clean_screen, self.review_screen):
                        sm.add_widget(s)
                    self.scan_screen.setup("scan")
                    self.clean_screen.setup("clean")
                    self.review_screen.refresh()
                self.root_box.add_widget(self.main)
                if is_android_app() and _android_intent_extra("safesweep_autotest") and not getattr(self, "_auto", False):
                    self._auto = True
                    Clock.schedule_once(lambda dt: self.autotest(), 1)
            else:
                self.root_box.add_widget(PermissionView())

        def on_resume(self):
            if self.main is None:
                self.check_access()

        def on_pause(self):
            return True

        @mainthread
        def set_status(self, text):
            self.status = text[-120:]

        def run_selftest(self, done_cb=None):
            self._selftest_popup, lbl = popup("Self-test", "Running… this takes a few seconds.", tall=True)
            lines: list[str] = []

            def job():
                from .selftest import run_selftest
                try:
                    ok, failures = run_selftest(lambda l: (lines.append(l), print("SELFTEST", l)))
                except Exception as e:
                    ok, failures = False, [repr(e)]
                self._selftest_done(lbl, lines, ok, failures, done_cb)

            threading.Thread(target=job, daemon=True).start()

        @mainthread
        def _selftest_done(self, lbl, lines, ok, failures, done_cb):
            head = ("[b][color=7CFC9A]All checks passed - SafeSweep works correctly on this device.[/color][/b]\n\n"
                    if ok else f"[b][color=ff8080]{len(failures)} check(s) failed.[/color][/b]\n\n")
            safe = (l.replace("&", "&amp;").replace("[", "&bl;").replace("]", "&br;") for l in lines)
            lbl.text = head + "\n".join(safe)
            self.set_status("Self-test passed." if ok else "Self-test FAILED - see report.")
            if done_cb:
                done_cb(ok)

        # ---- automated on-device test (only when launched with the safesweep_autotest extra) ----
        def autotest(self):
            print("AUTOTEST start")
            fast = {"min_age_hours": 0}  # test files were just copied onto the device

            def after_selftest(ok):
                print(f"AUTOTEST selftest ok={ok}")
                if getattr(self, "_selftest_popup", None):
                    self._selftest_popup.dismiss()
                Clock.schedule_once(lambda dt: start_scan(), 1)

            def start_scan():
                self.scan_screen.ids.where.text = "Downloads"
                self.scan_screen.start(fast, after_scan)

            def after_scan(res, stats):
                for f in res:
                    print(f"AUTOTEST scan {f.severity} rec={f.recommended} {os.path.basename(f.path)} | {f.reason}")
                print(f"AUTOTEST scan files={stats.get('files')} found={len(res)}")
                from .config import Settings
                from .feeds import status_text
                print(f"AUTOTEST feeds {status_text(Settings.load())}")
                Clock.schedule_once(lambda dt: start_clean(), 4)

            def start_clean():
                self.main.ids.sm.current = "clean"
                self.main.ids.clean_tab.state = "down"
                self.clean_screen.ids.where.text = "Downloads"
                self.clean_screen.start(fast, after_clean)

            def after_clean(res, stats):
                for f in res:
                    print(f"AUTOTEST clean rec={f.recommended} {os.path.basename(f.path)} | {f.reason}")
                print(f"AUTOTEST clean files={stats.get('files')} found={len(res)}")
                Clock.schedule_once(lambda dt: self.clean_screen.move_selected(after_move), 4)

            def after_move(ok, errors):
                print(f"AUTOTEST moved={len(ok)} errors={errors}")
                self.main.ids.sm.current = "review"
                self.main.ids.review_tab.state = "down"
                self.review_screen.refresh()
                print(f"AUTOTEST review items={len(self.review_screen.items)} folder={self.review_screen.folder}")
                print("AUTOTEST done")

            self.run_selftest(lambda ok: Clock.schedule_once(lambda dt: after_selftest(ok), 3))

    app = SafeSweepApp()
    app.run()


app = None

if __name__ == "__main__":
    run()
