#!/usr/bin/env bash
# Installs the APK on a running emulator, runs the app's automatic test mode and checks the results.
set -u
APK_DIR="${1:-apk}"
PKG=org.safesweep.safesweep
OUT=shots
mkdir -p "$OUT"
APK=$(ls "$APK_DIR"/*.apk | head -1)
echo "Installing $APK"
adb install -r -g "$APK" || { echo "INSTALL FAILED"; exit 1; }
adb shell appops set --uid "$PKG" MANAGE_EXTERNAL_STORAGE allow || adb shell appops set "$PKG" MANAGE_EXTERNAL_STORAGE allow

# Test files on the "phone"
TMP=$(mktemp -d)
python3 - "$TMP" <<'PY'
import os, sys
d = sys.argv[1]
eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
photo = os.urandom(300 * 1024)
files = {"eicar.com": eicar, "Invoice.pdf.apk": b"PK fake", "IMG_1001.jpg": photo, "IMG_1001 (1).jpg": photo,
         "video.mp4.part": b"x" * 5000, "notes.txt": b"normal file", "holiday.jpg": os.urandom(200 * 1024)}
for name, data in files.items():
    open(os.path.join(d, name), "wb").write(data)
PY
adb shell mkdir -p /sdcard/Download
for f in "$TMP"/*; do adb push "$f" "/sdcard/Download/" >/dev/null; done
adb shell ls -la /sdcard/Download

adb logcat -c
adb shell am start -n "$PKG/org.kivy.android.PythonActivity" --es safesweep_autotest 1
sleep 10
adb exec-out screencap -p > "$OUT/1-start.png"
shot=2
for i in $(seq 1 120); do
  sleep 3
  LOG=$(adb logcat -d)
  if (( i % 5 == 0 )); then adb exec-out screencap -p > "$OUT/$shot-progress.png"; shot=$((shot + 1)); fi
  if grep -q "AUTOTEST done" <<<"$LOG"; then break; fi
  if grep -q "Traceback" <<<"$LOG"; then echo "Python error detected"; break; fi
done
sleep 2
adb exec-out screencap -p > "$OUT/9-final.png"
adb logcat -d > "$OUT/logcat.txt"

echo "================ app output ================"
grep -E "AUTOTEST|SELFTEST|Traceback|Error|python" "$OUT/logcat.txt" | grep -vE "GLES|libEGL" | tail -150

fail=0
check() { if grep -qE "$2" "$OUT/logcat.txt"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
check "app started and ran its checks"         "AUTOTEST start"
check "self-test passed on the device"         "AUTOTEST selftest ok=True"
check "virus scan caught the EICAR test file"  "AUTOTEST scan high rec=True eicar.com"
check "virus scan caught the fake extension"   "AUTOTEST scan high rec=True Invoice.pdf.apk"
check "scan did not flag normal files"         "AUTOTEST scan files=[0-9]+ found=2"
check "cleanup found the duplicate photo"      "AUTOTEST clean rec=True IMG_1001 \(1\).jpg"
check "cleanup found the partial download"     "AUTOTEST clean rec=True video.mp4.part"
check "files were moved to the Review folder"  "AUTOTEST moved=2 errors=\[\]"
check "Review folder lists them"               "AUTOTEST review items=2"
check "finished"                               "AUTOTEST done"
if grep -q "Traceback" "$OUT/logcat.txt"; then echo "FAIL  Python error in log"; fail=1; fi
adb shell pidof "$PKG" >/dev/null && echo "PASS  app still running" || { echo "FAIL  app is not running"; fail=1; }
echo "Files left in Download:"; adb shell ls /sdcard/Download
adb shell ls /sdcard/SafeSweep/Review/files || true
exit $fail
