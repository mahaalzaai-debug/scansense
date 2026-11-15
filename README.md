# ScanSense

**See what a QR code actually does before you open it.**

ScanSense is a Python desktop app (Tkinter) that decodes a photo of a QR code and shows:

- the real website address, with the domain highlighted
- what the code contains: website, Wi-Fi details, contact information, or plain text
- whether Google Safe Browsing has flagged the link (the result says **"No known threat found"**, never "safe")
- **Compare mode:** upload two QR codes (e.g. a printed code and a sticker placed over it) and check whether they lead to the same destination, including look-alike domain detection (e.g. `example.com` vs `examp1e.com`)
- a scan history stored in SQLite (view, edit notes, delete)

## Requirements
Python 3.10+ (Tkinter is included with the Windows/macOS installers).

```
pip install -r requirements.txt
```

## API key (optional but recommended)
ScanSense uses the Google Safe Browsing Lookup API. Get a free key from the Google Cloud Console
(create a project, enable **Safe Browsing API**, Credentials -> Create API key).

Then do ONE of the following:
1. Create a file named `api_key.txt` next to `scansense_app.py` and paste the key in it (this file is git-ignored), or
2. Set the environment variable `SCANSENSE_API_KEY`.

Without a key the app still works, but links show "Reputation check not available" and only offline red-flag rules are applied.

## Run
```
python scansense_app.py
```
(On Windows you can use `py scansense_app.py`.)

## Demo
Click **Create demo QR codes** in the app. It creates two look-alike codes (`example.com` and `examp1e.com`).
Open the **Compare two codes** tab, load one into each slot, and press the compare button.

## Tests
```
python -m unittest -v test_scansense
```

## Design (OOP)
| Concept | Where |
|---|---|
| Abstraction / inheritance | `Payload` (ABC) -> `UrlPayload`, `WifiPayload`, `ContactPayload`, `OtherUriPayload`, `TextPayload` |
| Polymorphism | every payload implements `details()` and `comparison_key()`; the GUI treats them all the same |
| Interfaces | `QRDecoder` (-> `OpenCVQRDecoder`), `ReputationService` (-> `SafeBrowsingService`, `HeuristicService`) |
| Encapsulation | private fields with read-only properties; all SQL inside `ScanRepository` |
| Facade / separation | `ScanSenseService` hides the logic from the GUI; `ReputationChecker` combines online + offline checks |
| GUI | Tkinter: `ScanSenseApp`, reusable `ResultPanel`, `CompareTab`, `HistoryTab` |

## Limitations
- Reputation lists only know *reported* threats. A new malicious link may not be flagged yet.
- Blurry or damaged photos may fail to decode.

## Authors
Course CSC 2102 - Object-Oriented Programming, Fall 2026. Maha Alzaai and Fatma Saeed.
