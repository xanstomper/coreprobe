# Original research notes: AFC/mobilebackup2 surface on iOS 26.6.1 (A13)

Date: 2026-09-15/16 night session. Target: iPhone 11 (iPhone12,1, A13),
iOS 26.6.1 (23G83), AFU, trust-paired. All probes host-initiated, read-only
or self-cleaning. Context: CVE-2026-84598 (MobileBackup path traversal,
patched 26.7) has no public technical detail; these notes are our own
reconnaissance toward that bug class on the live vulnerable version.

## Results matrix (all observed tonight, first-hand)

| Surface | Probe | Result |
|---|---|---|
| AFC stat | `../` chains (1x-5x) | REJECTED (AfcException) |
| AFC stat | absolute `/etc/hosts`, `/private/var/Keychains` | READ_ERROR (interpreted as jail-relative, not found) |
| AFC stat | `%2e%2e`, unicode dots, NUL | REJECTED |
| AFC MAKE_LINK | symlink in-jail target | REJECTED status 1 |
| AFC MAKE_LINK | HARDLINK in-jail | REJECTED status 15 (perm) |
| AFC fopen | regular in-jail file (rel path) | OK (read verified, JPEG magic) |
| AFC fopen | absolute IN-JAIL path `/var/mobile/Media/...` | NOT FOUND - jail prefix stripped; absolute paths interpreted jail-relative |
| AFC fopen | through real symlink `PreviewWellImage.jpg` (LinkTarget ABSOLUTE in-jail) | PERM_DENIED (status 10) - symlinks exist, NOT followed for open |
| AFC stat | same symlink | OK: `S_IFLNK` + `LinkTarget` readable via GET_FILE_INFO |
| house_arrest | VendDocuments/VendContainer, all bundle ids incl. system | `InstallationLookupFailed` on every id - surface dead or newly gated on 26.x |
| crashreportmover | standard pull | WORKS: 250 files copied from out-of-jail /var/mobile/Library/Logs (JetsamEvent, Analytics, DiagnosticLogs) |
| crashreportcopy | start service | InvalidService on 26.6.1 |
| mobilebackup2 | version exchange (both orders) | silent - daemon wedged after restore-handshake experiment this session; recovers on reboot |

## Interpretation

1. Media jail hardened against every classic host-side path trick on 26.6.1.
2. Symlink follow-denial is the notable hardening: stat reveals LinkTarget
   but fopen refuses. If ANY device-side path follows relative symlinks out
   of its jail (crash-mover copying app containers? backup staging?), an
   app-planted `../../..` link becomes arbitrary read. This is the shape
   CVE-2026-84598's "path validation" fix likely addressed in MobileBackup.
   Test after reboot: restore staging DLMessageUploadItems with crafted
   manifest relative paths (host->device direction).
3. crashreportmover is a legitimate out-of-jail COPY primitive by design
   (logs only). CoreProbe already pulls it via `acquire all`.
4. house_arrest app-container vending appears removed/gated on 26.x -
   behavioral change vs iOS <=18.

## Next steps (post-reboot)
- re-run mb2 flows (backup via idevicebackup2, then List/restore staging)
- observe restore staging path resolution with crafted Manifest.plist
  `../../` domain paths - the leading CVE-2026-84598 candidate
- diff crash-mover copy list before/after app installs for container paths

## Session 2 addenda (01:40-01:50)

- mb2 still wedged (needs reboot) - restore-staging CVE-2026-84598 test pending.
- Service reachability on 26.6.1 (paired, AFU): pcapd, os_trace_relay,
  syslog_relay, mobileactivationd, atc, mobilesync REACHABLE;
  file_relay = ConnectionFailed (Number 3) even with escrow - notably
  DEAD where it was the classic LE arbitrary-read service;
  sysdiagnose/diagnostics_relay/mediaremoted/coredevice InvalidService.
- mobileactivationd on 26.x: all classic verbs (CreateSession, Activate
  family, GetActivationState, BeginActivation...) = 'unknown command' -
  protocol replaced; silent until host speaks; RE of the daemon binary
  needed to map new verbs. Matches activation-lock research interest.
- com.apple.atc (AirTraffic): framed [4B len][binary-plist] protocol;
  banner = Capabilities{GrappaSupportInfo v1}; Hello/GetCapabilities get
  no response (server-driven session). Grappa = content-cache file paths -
  potential path-based surface behind a completed handshake. First public
  documentation of 26.x ATC framing as far as we know.
- mobilesync: DL v400/100 alive; classic Ping responded with DeviceReady
  (flow moved to new sync commands).

## Session 3 addenda (04:00-04:31) - RESTORE PATH TRAVERSAL GATE CRACKED

Target: same live iPhone 11 / 26.6.1. Two front doors (AFC, backup2 backup
flow) are fully hardened. The RESTORE flow, however, accepts host-supplied
manifest paths - and traversal is not rejected.

PROTOCOL WORK (all first-hand against the device):
- Restore handshake: DLMessageVersionExchange (device-link v400) ->
  device requests host files via DLMessageDownloadFiles in this order:
  Manifest.plist -> Manifest.mbdb (NOT Manifest.db - legacy binary db).
- Manifest.plist schema that passes: Version "8.0" (float-parsed),
  SystemDomainsVersion "19.0". (3.0-5.0, 6-7, 12+ all rejected as
  "Unsupported properties/system domains version".)
- Manifest.mbdb header: magic "mbdb" + u32 LE major version + u16 count,
  then per-entry (domain, path, linktarget, datahash, unknown, mode,
  inode, uid, gid, mtimes, len, flags, props), footer count + 0xffffffff.
- RESULT: an mbdb whose entries carry dot-dot traversal paths
  ("../../Media/...", deep "../../../../../../var/tmp/...", and domain
  escape "SysContainerDomain-../../../../../../..") was ACCEPTED and
  parsed without any path-validation error.
- Restore then stops at the anti-theft gate: "Find My iPhone must be
  disabled before restoring (MBErrorDomain/211)".

INTERPRETATION:
- The 26.6.1 restore path does not validate manifest-relative traversal
  at parse time. This is the pre-26.7 state the advisory describes.
- Practical prerequisite we must record honestly: Find My iPhone must be
  off on the target for the restore branch to be reachable at all.
  (A device with Find My enabled cannot be restored from any host.)
- Next trigger (not yet run): with Find My temporarily disabled, serve
  the crafted manifest through the staged file requests and check
  whether trav1.txt lands at /var/mobile/Media (in-jail, harmless,
  verifiable over plain AFC listdir). If it does: CONFIRMED arbitrary
  write via restore staging. Same for /var/tmp/trav2.txt.
