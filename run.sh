#!/data/data/com.termux/files/usr/bin/bash
# mdeob -- run the APK deobfuscator in Termux
# usage: ./run.sh app.apk [options]     (all steps automatic by default)
set -e
cd "$(dirname "$0")"

# prefer the single-file dist (embeds smali.jar, baksmali.jar, apksigner.jar + keystore)
if [ -f mdeob_dist.py ]; then
  TOOL="mdeob_dist.py"
else
  TOOL="mdeob.py"
fi

command -v python3 >/dev/null 2>&1 || { echo "[run.sh] python3 missing -> pkg install python"; exit 1; }

# java is only needed to disassemble/rebuild; 'analyze' is stdlib-only
if [ "$#" -gt 0 ] && [ "$1" != "analyze" ]; then
  command -v java >/dev/null 2>&1 || { echo "[run.sh] java missing -> pkg install openjdk-17"; exit 1; }
fi

# no args -> show help
if [ "$#" -eq 0 ]; then
  exec python3 "$TOOL" --help
fi

exec python3 "$TOOL" "$@"
