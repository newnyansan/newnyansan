"""Android background service: the automatic daily threat check.

Started by DailyCheck's alarm (see packaging/android/java). Runs the same check as
`safesweep auto`, shows a notification only when something needs attention, schedules
the next run and exits.
"""
import os
import tempfile
import traceback


def main() -> None:
    from jnius import autoclass  # type: ignore
    ctx = autoclass("org.kivy.android.PythonService").mService
    daily = autoclass("org.safesweep.safesweep.DailyCheck")
    try:
        cache = ctx.getCacheDir().getAbsolutePath()
        os.environ["TMPDIR"] = cache
        tempfile.tempdir = cache
        from safesweep.mobile import has_storage_access, use_shared_home
        if not has_storage_access():
            daily.notifyResult(ctx, "SafeSweep can't check your files",
                               "Open SafeSweep and allow 'All files access' so the daily check can run.")
            return
        use_shared_home()
        from safesweep.auto import run_auto
        res = run_auto()
        print("AUTOCHECK", res.headline(), "|", res.details().replace("\n", " / "))
        if res.needs_attention:
            daily.notifyResult(ctx, res.headline(), res.details())
    except Exception:
        traceback.print_exc()
    finally:
        daily.markRun(ctx)
        daily.arm(ctx)


main()
