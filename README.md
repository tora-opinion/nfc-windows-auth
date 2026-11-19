# NFC Windows Sign-In with iPhone Express Card (Suica)

Hold an iPhone with an Express Card (Suica/PASMO) to a Sony RC-S300 reader to
sign in to Windows, the same way you would pass a train gate.

The reader appears on the Windows lock screen as its own entry under
**sign-in options**, alongside PIN and face, with a transit-IC icon and the
label *iPhone (Suica) でサインイン*.

```
┌──────────┐      ┌──────────┐      ┌──────────────────┐      ┌───────────────┐
│  iPhone  │      │ RC-S300  │      │  NfcAuthService  │      │ LogonUI       │
│ Express  │◄────►│ USB NFC  │◄────►│  (LocalSystem)   │◄────►│ Credential    │
│ Card     │ NFC  │ reader   │libusb│  tap tokens      │ pipe │ Provider DLL  │
└──────────┘      └──────────┘      └──────────────────┘      └───────────────┘
```

## What it is, and what it is not

This is a **Credential Provider**: a Windows extension point for adding a
sign-in method to the lock screen. It is not part of Windows Hello.

Windows Hello cannot be extended this way. Its biometric slots are fixed by the
OS to fingerprint, face and iris, so a custom factor can only ever appear there
as *"fingerprint"*, and the adapters that would make that work need a Microsoft
signature obtained through hardware certification. A Credential Provider is the
supported way to add a genuinely new sign-in method, and it is what lets this
one carry its own icon and name.

PIN and password sign-in keep working at all times. Nothing here can lock you
out of the machine.

## How the tap works

Apple Pay cards require Face ID. Express Card does not, and the system code is
what selects between them:

| FeliCa system code | Behaviour                         |
| ------------------ | --------------------------------- |
| `0xFFFF`           | Apple Pay (needs Face ID)         |
| `0x88B4`           | Apple Pay (needs Face ID)         |
| `0x0003`           | **Express Card, no interaction**  |

The RC-S300 is driven over CCID Escape commands on USB interface 1 (WinUSB);
its PC/SC interface cannot reach Express Card mode. See `src/rcs300.py`.

## Security model

- The reader service runs as **LocalSystem** and starts at boot, so a tap works
  before anyone has signed in.
- It serves tap events over the named pipe `\\.\pipe\NfcAuthTap`, whose DACL
  grants **SYSTEM only**. An ordinary user process cannot forge a tap.
- Each tap mints a **single-use nonce with a short TTL**. The provider must
  consume it, and the service re-arms only after the card has left the field.
- Card identifiers are stored as **HMAC-SHA-256 of the IDm** under a key in
  `C:\ProgramData\NfcAuth`, which is readable only by SYSTEM and local
  administrators. The raw IDm is never written to disk.

Two things this cannot defend against, by design:

- **A FeliCa IDm is a fixed, readable identifier.** Anything that can replay it
  can impersonate the card. Treat the tap as a convenient factor, not a strong
  one.
- **Stored passwords are recoverable by an administrator.** See below.

### Typed password vs. hands-free

By default a tap is the *first* factor: the tile unlocks and you type your
Windows password. Nothing secret is stored.

Running `set-credential` stores your password so a tap signs in on its own. The
blob is DPAPI-encrypted under the **machine** key, because LogonUI runs as
LocalSystem and has no user profile to unprotect a user-scoped blob with. Its
file ACL is therefore the only thing protecting it: anyone who obtains
administrator rights on this PC can recover that password. On a Microsoft
account that is the password to your whole Microsoft identity.

Use `clear-credential` to go back to typing it.

## Requirements

- Sony RC-S300 (PaSoRi), bound to WinUSB
- Windows 10 or 11, x64
- Python 3.9+ with `pywin32` and `pyusb`
- Visual Studio 2022 with the C++ x64 toolset (to build the provider)
- An iPhone with Express Card configured

## Install

Run from an **elevated** PowerShell prompt:

```powershell
py -3 -m pip install -r requirements.txt
.\Install-NfcAuth.ps1
```

This builds and registers the provider, installs and starts the service, and
removes the older file-signal setup if it is still present.

The service itself is copied to `C:\Program Files\NfcAuth`, because it runs as
LocalSystem and must not be startable from a directory you can edit without
administrator rights.

Then register your iPhone against your Windows account:

```powershell
# Local account
py -3 "C:\Program Files\NfcAuth\tools\nfc_cards.py" register --name iPhone --windows-user "$env:USERDOMAIN\$env:USERNAME"

# Microsoft account
py -3 "C:\Program Files\NfcAuth\tools\nfc_cards.py" register --name iPhone --windows-user "MicrosoftAccount\you@example.com"
```

Optionally enable hands-free sign-in, having read the warning above:

```powershell
py -3 "C:\Program Files\NfcAuth\tools\nfc_cards.py" set-credential --windows-user "MicrosoftAccount\you@example.com"
```

Lock the PC with <kbd>Win</kbd>+<kbd>L</kbd> and hold the iPhone to the reader.

## Managing cards

```powershell
py -3 "C:\Program Files\NfcAuth\tools\nfc_cards.py" list              # cards, and whether auto sign-in is set
py -3 "C:\Program Files\NfcAuth\tools\nfc_cards.py" remove --name iPhone
py -3 "C:\Program Files\NfcAuth\tools\nfc_cards.py" clear-credential  # back to typing the password
```

## Uninstall

```powershell
.\Uninstall-NfcAuth.ps1          # keeps registered cards
.\Uninstall-NfcAuth.ps1 -Purge   # also deletes C:\ProgramData\NfcAuth
```

If the lock screen ever misbehaves, sign in with your PIN or password, or boot
into Safe Mode, and run the uninstaller there.

## Layout

```
src/
  rcs300.py            RC-S300 driver, Express Card polling
  nfc_auth_service.py  LocalSystem service: reader loop and pipe server
  nfc_pipe.py          Pipe protocol, tap tokens, presence gate
  nfc_store.py         Protected state: cards, HMAC key, stored credential
  nfc_common.py        Config and logging helpers
tools/
  nfc_cards.py         Administrator CLI
credential_provider/
  src/                 The Credential Provider DLL
  assets/make_tile.py  Generates the tile artwork
  build.ps1            Release x64 build, tests and hardening checks
```

## Development

```powershell
py -3 -m pytest tests/           # Python tests
.\credential_provider\build.ps1  # builds the DLL and runs the C++ tests
```

## Credits and licence

MIT. System code `0x0003` was found by capturing USB traffic from Sony's
SFCard Viewer.

The tile artwork is original. "Suica" appears only as the name of the Express
Card the reader talks to; the Suica logo and mascot are trademarks of JR East
and are deliberately not used.
