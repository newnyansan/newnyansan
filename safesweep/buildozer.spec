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

requirements = python3,kivy,pyjnius,android,certifi
orientation = portrait
fullscreen = 0
icon.filename = %(source.dir)s/assets/icon.png
presplash.filename = %(source.dir)s/assets/presplash.png
android.presplash_color = #FFFFFF

# Storage access: Android 11+ uses "All files access" (MANAGE_EXTERNAL_STORAGE);
# older versions use the classic read/write permissions.
android.permissions = INTERNET, READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE, MANAGE_EXTERNAL_STORAGE
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
