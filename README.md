# mdeob — Android APK Deobfuscator

A single-file, Termux-friendly APK deobfuscation toolkit. It can:

- disassemble an APK's `classes*.dex` (via baksmali) and reassemble it (via smali)
- recover XOR-encoded string pools and inline them as `const-string`
- auto-detect and semantically rename R8/ProGuard-obfuscated classes
- neutralize simple integrity / anti-tamper gates
- rebuild the APK, page-align it in pure Python (no `zipalign` binary needed) and sign it (v2/v3)

`analyze` is **stdlib-only**. The `deob` / `rebuild` / `sign` commands need a Java runtime.

## Install (Termux)

```bash
pkg install python openjdk-17 unzip
termux-setup-storage                 # allow /sdcard access

git clone https://github.com/0xgf18/mdeob
cd mdeob
chmod +x run.sh && ./run.sh           # prints help
./run.sh /sdcard/Download/app.apk     # full pipeline, all steps automatic
```

Output is written to `/sdcard/Download/deobfuscated/`.

## Quick start

Everything is bundled into one file, `mdeob_dist.py` (it embeds `smali.jar`,
`baksmali.jar`, `apksigner.jar` and a throwaway test keystore, auto-extracted to
`runtime/` on first run). Just point it at an APK:

```bash
python3 mdeob_dist.py /sdcard/Download/app.apk
```

That runs the full pipeline with every step enabled and writes:

```
/sdcard/Download/deobfuscated/deobfuscated-app.apk
/sdcard/Download/deobfuscated/deobfuscation_report.json
```

`analyze` is stdlib-only and needs no Java:

```bash
./run.sh analyze /sdcard/Download/app.apk --json report.json
```

### Full CLI

```
mdeob analyze  <apk> [--json report.json]     # stdlib-only; no Java needed
mdeob deob     <apk> [options]                # full pipeline (all steps ON by default)
mdeob rebuild  <apk> --dex out.dex [--sign]
mdeob sign     <apk>
```

`deob` options:

| flag | default | meaning |
|------|---------|---------|
| `--out DIR` | `<apk dir>/deobfuscated/` | output directory |
| `--no-decode-strings` | on | disable XOR string recovery |
| `--no-auto-map` | on | disable semantic renaming |
| `--no-neutralize` | on | disable gate neutralization |
| `--no-sign` | on | do not sign the result |
| `--rename-map FILE` | | extra `OLD=NEW` rename pairs |
| `--ks`, `--ks-alias`, `--ks-pass`, `--key-pass` | bundled | custom signing key |

## Building the single-file dist

Put `baksmali.jar`, `smali.jar`, `apksigner.jar` and `mdeob.keystore` next to
`mdeob.py`, then:

```bash
python build_bundle.py     # -> mdeob_dist.py
```

## Signing key notice

The bundled `mdeob.keystore` (alias `mdeob`, password `mdeob123`) is a **throwaway
test key** used so the pipeline works out of the box. It is public and not
trusted for anything — use your own keystore (`--ks`) for real releases.

## Disclaimer

Use only on applications you own or are explicitly authorized to analyze.
