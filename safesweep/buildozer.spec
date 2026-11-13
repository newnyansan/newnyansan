# Android build for SafeSweep:  buildozer android debug   (output: bin/*.apk)
[app]
title = SafeSweep
package.name = safesweep
package.domain = org.safesweep
source.dir = .
source.include_exts = py,png,txt
source.include_patterns = main.py,safesweep/*.py,safesweep/data/*.txt,assets/icon.png
source.exclude_dirs = tests,packaging,bin,build,dist,.buildozer,__pycache__
version.regex = __version__ = ['"](.*)['"]
version.filename = %(source.dir)s/safesweep/__init__.py

# Only packages with python-for-android recipes: anything else triggers p4a's pip stage,
# which breaks multi-architecture builds. HTTPS uses Android's own certificate store.
requirements = python3,kivy,pyjnius,android
orientation = portrait
fullscreen = 0
icon.filename = %(source.dir)s/assets/icon.png
presplash.filename = %(source.dir)s/assets/presplash.png
android.presplash_color = #FFFFFF

# Storage access: Android 11+ uses "All files access" (MANAGE_EXTERNAL_STORAGE);
# older versions use the classic read/write permissions.
android.permissions = INTERNET, READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE, MANAGE_EXTERNAL_STORAGE, FOREGROUND_SERVICE, FOREGROUND_SERVICE_DATA_SYNC, POST_NOTIFICATIONS, USE_EXACT_ALARM, SCHEDULE_EXACT_ALARM, RECEIVE_BOOT_COMPLETED, WAKE_LOCK
# Daily automatic check: background service started by an exact daily alarm; a WorkManager job
# (survives reboots) re-arms the alarm. Java sources in packaging/android/java.
services = check:safesweep/android_service.py:foreground:foregroundServiceType=dataSync
android.enable_androidx = True
android.gradle_dependencies = androidx.work:work-runtime:2.9.1
android.add_src = %(source.dir)s/packaging/android/java

android.extra_manifest_application_arguments = %(source.dir)s/packaging/android/manifest_application_args.xml

android.api = 35
android.minapi = 24
android.ndk = 28c
android.archs = arm64-v8a, armeabi-v7a, x86_64
android.accept_sdk_license = True
android.allow_backup = False
android.release_artifact = apk
android.debug_artifact = apk

p4a.branch = master

[buildozer]
log_level = 2
warn_on_root = 0
