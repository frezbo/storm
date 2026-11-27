# Storm SecureBoot enrollment

Storm is a Minisforum UM790 Pro (board "Venus series", Shenzhen Meigao,
AMI Aptio 02.22.0058, BIOS 1.09 built 2023-11-20). It runs Talos with
SecureBoot using the keys of Omni's image factory (PK/KEK/db from the Omni
SecureBoot ISO). Enrolled 2026-11-22.

## Why the obvious paths fail on this firmware

- No Key Management, Expert Key Management or Factory Key Provision menu,
  in either Standard or Custom mode, with or without an Administrator
  password.
- Security > Secure Boot > Reset To Setup Mode deletes the keys, but the
  firmware reinstalls the factory keys on every restart (including
  "Save Changes and Reset" with Secure Boot disabled). A reboot into the
  ISO therefore never sees Setup Mode, so systemd-boot never offers
  enrollment. `secure-boot-enroll force` does not help: systemd-boot only
  looks at `loader/keys` when the firmware is in Setup or Audit Mode.
- Setting Secure Boot to Enabled while in Setup Mode is refused ("Secure
  Boot can be enabled when System in User Mode"); saving with Enabled
  attempted made the firmware provision the factory keys and enforce them,
  so the old (unsigned) Talos failed with "Secure Boot Violation".
- Save & Exit > Boot Override lists no devices, and its EFI Shell entry
  blanks and returns.
- Switching Secure Boot Mode to Custom prompts "Install factory defaults";
  answer No.

## What worked: enroll in the same boot session

The key deletion takes effect immediately; only a restart brings the
factory keys back. So enroll without restarting:

1. Write the Omni SecureBoot ISO to a USB stick
   (`omnictl download iso --secureboot --talos-version <v> --extensions ...`;
   it contains `loader/keys/auto/{PK,KEK,db}.auth`).
2. Firmware (Del at power-on): Security > Secure Boot: Secure Boot
   `Disabled`, mode `Custom`. Reset To Setup Mode > Yes, then **Cancel** at
   "Reset without saving?". System Mode now reads `Setup`.
3. Back out to the front page (tiles) without saving, choose **UEFI Shell**.
4. In the shell:

   ```
   map -r
   dmpstore SetupMode      # must be 01
   FS0:                    # the USB CDROM filesystem
   EFI\BOOT\BOOTX64.EFI
   ```

5. systemd-boot shows "Enroll Secure Boot keys: auto"; let it enroll (do
   not press a key during the countdown). It reboots.
6. Firmware: System Mode `User`; set Secure Boot `Enabled`; Save Changes
   and Reset.
7. The ISO boots in maintenance with `securitystate` `secureBoot: true`.
   Remove the stick before Omni's install reboots, or the ISO halts on
   `talos.halt_if_installed`.

## Wiping an installed Talos from the ISO

Omni's cluster delete wipes only STATE and EPHEMERAL; META stays, so the
ISO halts ("already installed"). Omni also refuses `talosctl reset`
(`PermissionDenied`). The ISO's systemd-boot entry "(Reset system disk)"
(`talos.experimental.wipe=system`) wipes the whole system disk before the
halt check. The menu may be hidden by `LoaderConfigTimeout`; tap Space
during boot to show it.

## Recovery

Clearing CMOS (or Restore Factory Keys) restores the vendor and Microsoft
keys; Talos then fails to boot until Secure Boot is disabled. The enrolled
db holds only the Omni factory key, so Microsoft-signed option ROMs do not
load; the integrated GPU's firmware is part of the BIOS and still works.
