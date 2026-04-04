# NFC Windows Authentication with iPhone Express Card (Suica)

Windows Hello-style login using iPhone's Express Card (Suica/PASMO) and Sony RC-S300 NFC reader.

## Key Discovery

**System code `0x0003` triggers iPhone Express Card mode!**

Standard FeliCa system codes like `0xFFFF` (wildcard) or `0x88B4` (transit IC) activate Apple Pay, which requires Face ID/Touch ID authentication.

The magic system code `0x0003` activates Express Card (Suica) mode, allowing seamless NFC communication without user interaction - just like at a train station gate.

## How It Works

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   iPhone    │      │   RC-S300   │      │   Windows   │
│ (Express    │◄────►│  (USB NFC   │◄────►│  Auth       │
│  Card/Suica)│      │   Reader)   │      │  Daemon     │
└─────────────┘      └─────────────┘      └─────────────┘
       │                    │                    │
       │  System 0x0003     │                    │
       │◄───────────────────│                    │
       │                    │                    │
       │  IDm Response      │                    │
       │───────────────────►│                    │
       │                    │   IDm Match        │
       │                    │───────────────────►│
       │                    │                    │
       │                    │   Unlock/Login     │
       │                    │                    ▼
```

## Technical Details

### RC-S300 Communication

The RC-S300 uses CCID Escape commands over USB Interface 1 (WinUSB):

```
Header: 6B [len_lo] [len_hi] 00 00 00 [seq] 00 00 00
Data:   FF 50 00 01 00 [len_hi] [len_lo] [TLV data] 00 00 00

TLV Format:
  5F 46 04 [timeout_us LE]           - Timeout in microseconds
  95 82 [len_hi] [len_lo] [felica]   - Transceive command

FeliCa Polling:
  06 00 [sys_hi] [sys_lo] [req] [slot]
  
Express Card Magic:
  06 00 00 03 01 00   ← System code 0x0003!
```

### Session Initialization

```python
# 1. End previous session
FF 50 00 00 02 82 00 00  # Tag 0x82

# 2. Start new session  
FF 50 00 00 02 81 00 00  # Tag 0x81

# 3. RF Off
FF 50 00 00 02 83 00 00  # Tag 0x83
# Wait 30ms

# 4. RF On
FF 50 00 00 02 84 00 00  # Tag 0x84
# Wait 21ms

# 5. Switch to FeliCa protocol
FF 50 00 02 04 8F 02 03 00 00
```

### Why 0x0003?

This was discovered by capturing USB packets from Sony's SFCard Viewer web application.

| System Code | Behavior |
|-------------|----------|
| `0xFFFF` | Triggers Apple Pay (requires Face ID) |
| `0x88B4` | Triggers Apple Pay (requires Face ID) |
| `0x0003` | **Triggers Express Card (no auth!)** |

## Requirements

- Sony RC-S300 (PaSoRi) USB NFC Reader
- Windows 10/11
- Python 3.8+
- libusb-1.0.dll
- iPhone with Express Card (Suica/PASMO) configured

## Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/nfc-windows-auth.git
cd nfc-windows-auth

# Install dependencies
pip install pyusb

# Download libusb (if not present)
# Place libusb-1.0.dll in daemon/ folder
```

## Usage

### Register Your Card

```bash
python src/auth_daemon.py register "My iPhone"
# Place iPhone on reader when prompted
```

### Run Authentication Daemon

```bash
python src/auth_daemon.py run
```

### Test Card Detection

```bash
python src/auth_daemon.py test
```

### List Registered Cards

```bash
python src/auth_daemon.py list
```

## Project Structure

```
nfc-windows-auth/
├── src/
│   ├── rcs300.py        # RC-S300 driver with Express Card support
│   └── auth_daemon.py   # Windows authentication daemon
├── daemon/
│   └── libusb-1.0.dll   # USB library
├── config.json          # Registered cards and settings
└── README.md
```

## Security Notes

- IDm is hashed (SHA-256) before storage
- Original IDm is never saved to disk
- Consider using Windows Credential Provider for production use

## Known Limitations

- Requires libusb/WinUSB driver for RC-S300
- PC/SC interface (Interface 0) cannot trigger Express Card
- Some iPhone models may behave differently

## Credits

- Sony NFC Port Library (reverse-engineered for system code discovery)
- SFCard Viewer web application (USB packet capture reference)

## License

MIT License

## Contributing

PRs welcome! Especially for:
- Windows Credential Provider integration
- Support for other NFC readers
- Better unlock mechanism
