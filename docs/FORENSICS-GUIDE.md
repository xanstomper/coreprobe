# Forensics Guide — artifact parsing & analysis

Everything here works on standard logical backups, BFU pulls, sysdiagnose
bundles, or full filesystem extractions. All parsers read real data and
tolerate missing fields — they never invent rows.

## Acquisition → artifacts in one flow

```bash
opensleuth acquire all --out case          # backup + media + apps + report
opensleuth dump <backup> -o case/report    # parse → CSVs + artifacts.json + HTML report
```

## App database discovery (breadth)

```bash
opensleuth appcatalog list                 # 44-app catalog w/ known DB paths
opensleuth appcatalog inventory <root>     # every sqlite/storedata file + tables/rows/cols
opensleuth appcatalog extract <db> <table> --out t.csv [--where "..."]
```

Verified match set includes WhatsApp chatstorage, SMS sms.db,
CallHistory, Safari History.db, Notes NoteStore, Health, Chrome History.

## iLEAPP bridge (100+ parsers)

```bash
opensleuth ileapp run <extraction> --out case/ileapp    # requires iLEAPP installed
opensleuth ileapp breath <case> --ileapp-out case/ileapp --out case/breath
```

## Crash logs (.ips)

```bash
opensleuth crashlogs <root>
#   dual-JSON .ips: process, exception type, faulting frame/symbol,
#   bundle, OS version, timestamps → incident timeline
```

## Wireless

```bash
opensleuth wireless <root>
#   WiFi known networks (SSID/BSSID/security/hidden)
#   Bluetooth paired + recent devices ("Subject Car [paired]" evidence)
```

## Sysdiagnose (richest no-exploit artifact)

```bash
opensleuth sysdiagnose extract <tarball> --out case/sd
opensleuth sysdiagnose inventory case/sd
#   categorizes: location, network, power/battery, cellular, diagnostics,
#   device-info, bluetooth, notifications, app-usage
```

## knowledgeC (pattern of life)

```bash
opensleuth knowledgec <root-or-db>
#   ZOBJECT behavior stream: app-focus, lock/unlock, notifications,
#   siri, location-visits — Apple's own log of the user's day,
#   with top-apps summary
```

## Super-timeline

```bash
python3 -m opensleuth timeline artifacts.json --out case/timeline.csv
#   merges SMS/calls/notes/Safari + any timestamped sources
#   Apple-epoch aware, CSV + JSON output
```

## Keybag / decryption

```bash
opensleuth keybag status <bag>             # per-class usable-now report
opensleuth keybag backupbag <Manifest.plist>
opensleuth keybag unwrap <bag> --uid-key <k> --out class-keys.json
opensleuth acquire bfu-decrypt <file> --cprotect <blob> --class-key <hex>
```

## Native core (fast hashing)

```bash
opensleuth cxx hash --sha1 <files>         # ~150 MiB/s
opensleuth cxx manifest <dir> --out m.csv  # chain-of-custody manifest
opensleuth cxx mbdb <Manifest.mbdb>        # parse backup index, flag traversals
```

## UI

**Artifacts** page (Ctrl+9): crash logs / wireless / sysdiagnose /
knowledgeC / super-timeline buttons over any extraction root.
**Reports** page renders the HTML report; **Applications** shows app inventory.
