# Research Guide — the zero-day research program

**What this is:** the complete open-source loop for finding new iOS
exploits (the method that produced checkm8 and usbliter8), structured as
a campaign with honest verdicts. **What it is not:** a download of
working 0-days. A finding enters the catalog only via: observed crash →
reproduced → root-caused → public writeup.

## The pipeline

```
dfu-usbmon.sh (passive DFU USB capture)
  → opensleuth silicon --trace <capture> --corpus corpus.csv
  → python3 dfu-fuzz.py corpus.csv <iterations>   (mutation fuzz on real device)
  → opensleuth campaign run <id> --capture <f>    (sessions + leads)
  → opensleuth campaign triage L001 promising     (verdict ladder)
  → opensleuth silicon --notebook <lab> --note "…" (research log)
```

## 1. Capture (lab kit)

```bash
opensleuth silicon --lab ~/research-lab --chip A13
cd ~/research-lab
./session-log.sh                 # timestamped research log
sudo ./dfu-usbmon.sh             # start BEFORE entering DFU
# enter DFU on the lawful research device
```

## 2. Trace analysis + corpus

```bash
opensleuth silicon --trace dfu-capture-*.pcapng.txt
#   decodes DFU class requests (DETACH/DNLOAD/UPLOAD/GETSTATUS/GETSTATE/ABORT)
#   flags anomalies: unusual/large DNLOAD lengths, GETSTATUS storms, DETACH renumeration

opensleuth silicon --trace <capture> --corpus corpus.csv
#   distinct requests → mutation corpus (boundary lengths/values + bit flips)
```

## 3. Fuzz (real device)

```bash
python3 dfu-fuzz.py corpus.csv 500
#   drives DFU control transfers via pyusb; device death/hang/stall are
#   the signals that precede memory-safety bugs
```

## 4. Campaign (sessions compound)

```bash
opensleuth campaign new a13-dfu --target DFU --chip A13 --ios 26.6.1
opensleuth campaign run <id> --capture cap.txt        # live fuzz
opensleuth campaign run <id> --capture cap.txt --dry  # analysis only
opensleuth campaign status                            # sessions + leads
opensleuth campaign triage L001 promising --notes "reproduced 3x"
```

Verdict ladder: `observed → promising (repro) → escalated (root cause) →
finding (public writeup)`. State persists in `~/.coreprobe/campaign.json`.

## 5. Attack-surface targeting

```bash
opensleuth surface
#   ranks tracked Apple-patched CVEs into research targets by acquisition
#   value (PRIME = kernel-exec/root/keychain/network-reachable) and
#   component richness (Kernel x4, AVEVideoEncoder x3, CoreMedia x2)
```

These are *patched* CVEs — they map where Apple admits the surface is
exploitable. New bugs are found by the loop above, not assumed.

## 6. Exploit-dev toolbox

```bash
opensleuth firmware identify|scan|img4|extract   # IPSW/IMG4/IM4P parsing
opensleuth trustcache build|parse                # CD-hash whitelists
opensleuth patches --target kernel|sep|iboot|sptm # documented patch classes
```

## 7. Disclosure hunting (automated)

`opensleuth research` sweeps Apple advisories + public sources; the
recommended deployment is a cron/systemd timer every 2h. Each sweep
updates `~/.coreprobe/research-state.json` (208 CVEs tracked as of
2026-09-16) and logs to `~/.coreprobe/research-log.txt`.

## Rules

1. Lawful research devices only.
2. Log everything (session-log + notebook).
3. No fabricated findings — ever.
4. Credit original researchers; verify provenance (e.g. usbliter8's
   Magnet Forensics litigation history is documented in the catalog).
