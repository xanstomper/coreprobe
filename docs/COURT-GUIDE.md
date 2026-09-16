# Court Guide — chain of custody & evidence integrity

## Certify (create the sealed record)

```bash
opensleuth certify <case-dir> --out <out-dir> --examiner "Jane Doe"
#   walks the case dir, hashes every file with the native C++ core
#   (~150 MiB/s), writes:
#     evidence-manifest.csv   sha256,size,relpath
#     sealed-report.json      examiner signature block + per-file hashes
#     sealed-report.html      court-presentable rendering
#     seal.key                HMAC key (0600) — store securely!
```

## Verify (integrity check at any later time)

```bash
opensleuth certify --verify <sealed-report.json>
#   → seal VALID/INVALID + per-file TAMPERED/missing detection
```

Verified behaviors (tested): clean verify → INTEGRITY OK; modified file
→ TAMPERED flagged by name; deleted file → missing; wrong key → seal
INVALID.

## Passphrase mode

```bash
OPENSLEUTH_SEAL_PHRASE="..." opensleuth certify ... # --passphrase-env
```

## Recommended case workflow

1. `acquire` into the case dir
2. `certify` immediately after acquisition (fixes the hash baseline)
3. Analyze freely (timeline, parsers) — analysis never writes to evidence
4. `certify --verify` before producing the final report
5. Ship report + sealed-report.json (+ keep seal.key offline)

## iCloud (lawful authorization)

```bash
opensleuth acquire icloud --warrant <case-id> --username ... --password ... --out case
#   refuses to run without --warrant; account-level services only
```

## UI

Evidence page (Ctrl+8): certify-create form + verify with pass/fail
rendering (also usable as a demo of tamper detection).
