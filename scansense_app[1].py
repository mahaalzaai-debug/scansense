"""
ScanSense - see what a QR code actually does before you open it.
SINGLE-FILE VERSION: save as scansense_app.py, then run it (Spyder: press F5).

Needs:  pip install opencv-python Pillow numpy
Optional: put a free Google Safe Browsing API key in API_KEY below.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import unicodedata
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from PIL import Image, ImageTk

# ---------------------------------------------------------------------------
# SETTINGS - paste your API key between the quotes (leave "" to run without one)
# ---------------------------------------------------------------------------
API_KEY = ""

try:
    APP_DIR = Path(__file__).resolve().parent
except NameError:  # some consoles don't define __file__
    APP_DIR = Path.cwd()
DB_FILE = APP_DIR / "scansense.db"
KEY_FILE = APP_DIR / "api_key.txt"   # put your key in this file (it is git-ignored)


def load_api_key() -> str:
    """Key lookup order: API_KEY above, env var SCANSENSE_API_KEY, then api_key.txt."""
    if API_KEY:
        return API_KEY
    if os.environ.get("SCANSENSE_API_KEY"):
        return os.environ["SCANSENSE_API_KEY"]
    try:
        return KEY_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""

# ======================================================================
# MODELS
# ======================================================================
# Two-part public suffixes we want to treat as a single "TLD".
# (A full list would need the Public Suffix List; this covers the common ones.)
_TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "co.in", "co.za", "com.br", "com.cn", "com.sa",
    "com.eg", "com.tr", "co.ae", "gov.ae", "ac.ae",
}


class Payload(ABC):
    """Abstract base class for everything a QR code can contain."""

    #: Human readable name of the content type, overridden by subclasses.
    KIND = "Unknown"

    def __init__(self, raw: str):
        self._raw = raw  # protected: use the read-only property below

    @property
    def raw(self) -> str:
        """The exact text stored in the QR code."""
        return self._raw

    @property
    def kind(self) -> str:
        return self.KIND

    @abstractmethod
    def details(self) -> list[tuple[str, str]]:
        """Return (label, value) pairs describing the content."""

    @abstractmethod
    def comparison_key(self) -> str:
        """Normalised string used to decide if two codes 'say the same thing'."""

    def is_link(self) -> bool:
        return False

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._raw[:40]!r})"


class UrlPayload(Payload):
    """A web link (http / https)."""

    KIND = "Website link"

    def __init__(self, raw: str):
        super().__init__(raw)
        text = raw.strip()
        self._url = text
        self._parsed = urlparse(text)

    @property
    def url(self) -> str:
        return self._url

    @property
    def scheme(self) -> str:
        return self._parsed.scheme.lower()

    @property
    def hostname(self) -> str:
        return (self._parsed.hostname or "").lower()

    @property
    def is_ip_address(self) -> bool:
        return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", self.hostname))

    @property
    def registered_domain(self) -> str:
        """The part of the host a person actually 'owns' (e.g. paypal.com)."""
        host = self.hostname
        if not host or self.is_ip_address:
            return host
        parts = host.split(".")
        if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_PART_SUFFIXES:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    @property
    def subdomain(self) -> str:
        host, dom = self.hostname, self.registered_domain
        return host[: -len(dom)].rstrip(".") if host.endswith(dom) else ""

    def split_for_highlight(self) -> tuple[str, str, str]:
        """Split the URL into (before_domain, domain, after_domain).

        The GUI colours the middle part so the real destination stands out.
        """
        dom = self.registered_domain
        idx = self._url.lower().find(dom) if dom else -1
        if idx < 0:
            return self._url, "", ""
        return self._url[:idx], self._url[idx: idx + len(dom)], self._url[idx + len(dom):]

    def is_link(self) -> bool:
        return True

    def details(self) -> list[tuple[str, str]]:
        rows = [
            ("Full address", self._url),
            ("Real domain", self.registered_domain or "(none)"),
            ("Secure (https)", "Yes" if self.scheme == "https" else "No"),
        ]
        if self.subdomain:
            rows.insert(2, ("Subdomain", self.subdomain))
        return rows

    def comparison_key(self) -> str:
        path = self._parsed.path.rstrip("/")
        query = f"?{self._parsed.query}" if self._parsed.query else ""
        return f"{self.hostname}{path}{query}".removeprefix("www.")


class OtherUriPayload(Payload):
    """mailto:, tel:, sms:, geo: ... links."""

    KIND = "Action link"

    def __init__(self, raw: str):
        super().__init__(raw)
        self._scheme = raw.split(":", 1)[0].lower()

    def details(self) -> list[tuple[str, str]]:
        return [("Action", self._scheme), ("Value", self._raw.split(":", 1)[-1])]

    def comparison_key(self) -> str:
        return self._raw.strip().lower()


class WifiPayload(Payload):
    """Wi-Fi join details: WIFI:T:WPA;S:name;P:password;;"""

    KIND = "Wi-Fi details"

    def __init__(self, raw: str):
        super().__init__(raw)
        self._fields = self._parse(raw)

    @staticmethod
    def _parse(raw: str) -> dict[str, str]:
        body = raw[5:]  # strip "WIFI:"
        fields: dict[str, str] = {}
        for part in re.split(r"(?<!\\);", body):
            if ":" in part:
                key, value = part.split(":", 1)
                fields[key.strip().upper()] = re.sub(r"\\(.)", r"\1", value)
        return fields

    @property
    def ssid(self) -> str:
        return self._fields.get("S", "")

    @property
    def security(self) -> str:
        return self._fields.get("T", "nopass") or "nopass"

    def details(self) -> list[tuple[str, str]]:
        has_pw = bool(self._fields.get("P"))
        return [
            ("Network name", self.ssid or "(hidden)"),
            ("Security", self.security),
            ("Password included", "Yes (hidden for safety)" if has_pw else "No"),
        ]

    def comparison_key(self) -> str:
        return f"wifi:{self.ssid}:{self.security}"


class ContactPayload(Payload):
    """Contact card in vCard or MECARD format."""

    KIND = "Contact information"

    def __init__(self, raw: str):
        super().__init__(raw)
        self._fields = self._parse(raw)

    @staticmethod
    def _parse(raw: str) -> dict[str, str]:
        fields: dict[str, str] = {}
        if raw.upper().startswith("MECARD:"):
            for part in re.split(r"(?<!\\);", raw[7:]):
                if ":" in part:
                    k, v = part.split(":", 1)
                    fields.setdefault(k.upper(), v)
            return fields
        for line in raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                key = k.split(";")[0].upper()
                if key in {"FN", "N", "TEL", "EMAIL", "ORG", "URL"}:
                    fields.setdefault(key, v)
        return fields

    def details(self) -> list[tuple[str, str]]:
        name = self._fields.get("FN") or self._fields.get("N", "")
        rows = [("Name", name.replace(";", " ").replace(",", " ").strip())]
        for label, key in (("Phone", "TEL"), ("Email", "EMAIL"),
                           ("Organisation", "ORG"), ("Website", "URL")):
            if key in self._fields:
                rows.append((label, self._fields[key]))
        return rows

    def comparison_key(self) -> str:
        return "contact:" + "|".join(v for _, v in self.details())


class TextPayload(Payload):
    """Anything else - plain text."""

    KIND = "Plain text"

    def details(self) -> list[tuple[str, str]]:
        return [("Text", self._raw), ("Length", f"{len(self._raw)} characters")]

    def comparison_key(self) -> str:
        return " ".join(self._raw.split())


def parse_payload(raw: str) -> Payload:
    """Factory: pick the right Payload subclass for the decoded text."""
    text = raw.strip()
    upper = text.upper()
    if re.match(r"^https?://", text, re.I):
        return UrlPayload(text)
    if upper.startswith("WIFI:"):
        return WifiPayload(text)
    if upper.startswith("BEGIN:VCARD") or upper.startswith("MECARD:"):
        return ContactPayload(text)
    if re.match(r"^(mailto|tel|sms|smsto|geo):", text, re.I):
        return OtherUriPayload(text)
    # "example.com/abc" with no scheme - treat as a link, add https for parsing
    if re.fullmatch(r"(www\.)?[\w-]+(\.[\w-]+)+(/\S*)?", text):
        return UrlPayload("http://" + text)
    return TextPayload(text)


# ======================================================================
# DECODER
# ======================================================================
class DecodeError(Exception):
    """Raised when an image cannot be read or contains no readable QR code."""


class QRDecoder(ABC):
    """Interface: anything that can turn an image file into QR text."""

    @abstractmethod
    def decode(self, image_path: str) -> str:
        ...


class OpenCVQRDecoder(QRDecoder):
    """Decodes with OpenCV's built-in detector.

    Photos of printed codes are often small, blurry or low-contrast, so we
    try several pre-processing variants before giving up.
    """

    def __init__(self) -> None:
        self._detector = cv2.QRCodeDetector()

    @staticmethod
    def _load(image_path: str) -> np.ndarray:
        path = Path(image_path)
        if not path.is_file():
            raise DecodeError(f"File not found: {image_path}")
        try:
            # np.fromfile + imdecode also works with non-ASCII paths on Windows
            data = np.fromfile(str(path), dtype=np.uint8)
            img = cv2.imdecode(data, cv2.IMREAD_COLOR)
        except Exception as exc:  # pragma: no cover - defensive
            raise DecodeError(f"Could not read image: {exc}") from exc
        if img is None:
            raise DecodeError("This file is not a valid image.")
        return img

    def _variants(self, img: np.ndarray):
        """Yield progressively more aggressive versions of the image."""
        yield img
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        yield gray
        h, w = gray.shape
        # very large photos: shrink; small ones: enlarge
        scale = 1000 / max(h, w)
        if scale < 1 or scale > 1.5:
            yield cv2.resize(gray, None, fx=scale, fy=scale,
                             interpolation=cv2.INTER_AREA if scale < 1 else cv2.INTER_CUBIC)
        yield cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                    cv2.THRESH_BINARY, 41, 10)
        # add a white quiet-zone border, which some photos crop away
        yield cv2.copyMakeBorder(gray, 60, 60, 60, 60, cv2.BORDER_CONSTANT, value=255)

    def decode(self, image_path: str) -> str:
        img = self._load(image_path)
        for variant in self._variants(img):
            try:
                text, _, _ = self._detector.detectAndDecode(variant)
            except cv2.error:
                continue
            if text:
                return text
        raise DecodeError("No QR code could be read in this image. "
                          "Try a sharper, closer, well-lit photo.")


# ======================================================================
# REPUTATION
# ======================================================================
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "qrco.de"}
RISKY_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "work"}

# Verdict constants (used by the GUI for colours)
FLAGGED = "FLAGGED"
NO_THREAT = "NO_KNOWN_THREAT"
UNCHECKED = "UNCHECKED"

VERDICT_TEXT = {
    FLAGGED: "FLAGGED as dangerous",
    NO_THREAT: "No known threat found",
    UNCHECKED: "Reputation check not available",
}


@dataclass
class ReputationResult:
    verdict: str = UNCHECKED
    threats: list[str] = field(default_factory=list)      # from the API
    warnings: list[str] = field(default_factory=list)     # local heuristics
    note: str = ""

    @property
    def headline(self) -> str:
        return VERDICT_TEXT[self.verdict]


class ReputationError(Exception):
    """Network / API problem while checking a link."""


class ReputationService(ABC):
    @abstractmethod
    def check(self, payload: UrlPayload) -> list[str]:
        """Return a list of findings (empty list = nothing found)."""


class HeuristicService(ReputationService):
    """Cheap, offline red-flag detection."""

    def check(self, payload: UrlPayload) -> list[str]:
        out: list[str] = []
        host = payload.hostname
        if payload.scheme == "http":
            out.append("Connection is not encrypted (http, not https).")
        if payload.is_ip_address:
            out.append("Link points to a raw IP address instead of a named website.")
        if "xn--" in host:
            out.append("Domain uses punycode (xn--), which can disguise look-alike characters.")
        if "@" in payload.url.split("//", 1)[-1].split("/")[0]:
            out.append("Link contains '@' before the host - the real destination may be hidden.")
        if payload.registered_domain in SHORTENERS:
            out.append("Link shortener: the final destination is hidden until opened.")
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in RISKY_TLDS:
            out.append(f"Domain ends in .{tld}, which is frequently abused.")
        if host.count(".") >= 4:
            out.append("Unusually many subdomains.")
        if re.search(r"(login|verify|secure|account|update|wallet)", host) and payload.subdomain:
            out.append("Sensitive-sounding word in a subdomain (common in phishing).")
        return out


class SafeBrowsingService(ReputationService):
    """Google Safe Browsing Lookup API v4 (free API key required)."""

    ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"

    def __init__(self, api_key: str | None = None, timeout: float = 8.0):
        self._api_key = api_key or load_api_key()
        self._timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def _build_request_body(self, url: str) -> dict:
        return {
            "client": {"clientId": "scansense", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

    @staticmethod
    def parse_response(data: dict) -> list[str]:
        names = {"MALWARE": "Malware", "SOCIAL_ENGINEERING": "Phishing / social engineering",
                 "UNWANTED_SOFTWARE": "Unwanted software",
                 "POTENTIALLY_HARMFUL_APPLICATION": "Potentially harmful app"}
        return sorted({names.get(m.get("threatType"), m.get("threatType", "Unknown"))
                       for m in data.get("matches", [])})

    def check(self, payload: UrlPayload) -> list[str]:
        if not self.configured:
            raise ReputationError("No API key set (see README: api_key.txt).")
        body = json.dumps(self._build_request_body(payload.url)).encode()
        req = urllib.request.Request(self.ENDPOINT.format(key=self._api_key), data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return self.parse_response(json.loads(resp.read().decode() or "{}"))
        except urllib.error.HTTPError as exc:
            raise ReputationError(f"API rejected the request (HTTP {exc.code}). "
                                  "Check your API key.") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ReputationError("Could not reach the reputation service. "
                                  "Check your internet connection.") from exc
        except ValueError as exc:
            raise ReputationError("Unexpected reply from the reputation service.") from exc


class ReputationChecker:
    """Facade combining the online API with the offline heuristics."""

    def __init__(self, online: ReputationService | None = None,
                 offline: ReputationService | None = None):
        self._online = online or SafeBrowsingService()
        self._offline = offline or HeuristicService()

    def evaluate(self, payload: UrlPayload) -> ReputationResult:
        result = ReputationResult(warnings=self._offline.check(payload))
        try:
            threats = self._online.check(payload)
        except ReputationError as exc:
            result.verdict, result.note = UNCHECKED, str(exc)
            return result
        if threats:
            result.verdict, result.threats = FLAGGED, threats
        else:
            result.verdict = NO_THREAT
            result.note = ("Not on the reputation service's list of known threats. "
                           "This does not guarantee the link is safe.")
        return result


# ======================================================================
# COMPARER
# ======================================================================
SAME = "SAME"
SAME_SITE = "SAME_SITE"
DIFFERENT = "DIFFERENT"


@dataclass
class ComparisonResult:
    outcome: str
    summary: str
    notes: list[str] = field(default_factory=list)


def edit_distance(a: str, b: str) -> int:
    """Classic Levenshtein distance (small strings only)."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def has_non_ascii(text: str) -> bool:
    return any(ord(c) > 127 for c in text)


class QRComparer:
    """Decides whether two payloads lead to the same destination."""

    def compare(self, a: Payload, b: Payload) -> ComparisonResult:
        if a.comparison_key() == b.comparison_key():
            return ComparisonResult(SAME, "Both codes lead to the same destination.")
        if isinstance(a, UrlPayload) and isinstance(b, UrlPayload):
            return self._compare_urls(a, b)
        return ComparisonResult(
            DIFFERENT, "The codes contain different content.",
            [f"Code A is: {a.kind}", f"Code B is: {b.kind}"])

    @staticmethod
    def _compare_urls(a: UrlPayload, b: UrlPayload) -> ComparisonResult:
        da, db = a.registered_domain, b.registered_domain
        if da == db:
            return ComparisonResult(
                SAME_SITE, f"Same website ({da}) but a different page.",
                [f"A: {a.url}", f"B: {b.url}"])
        notes = [f"A goes to {da}", f"B goes to {db}"]
        dist = edit_distance(da, db)
        if dist <= 2:
            notes.append(f"The domains differ by only {dist} character(s) - "
                         "a classic look-alike trick.")
        if has_non_ascii(a.hostname) or has_non_ascii(b.hostname) \
                or "xn--" in a.hostname or "xn--" in b.hostname:
            notes.append("One domain contains non-standard characters that can imitate letters.")
        # Unicode confusables like Cyrillic 'а' vs Latin 'a'
        for name, host in (("A", a.hostname), ("B", b.hostname)):
            scripts = {unicodedata.name(c, "?").split()[0] for c in host if c.isalpha()}
            if len(scripts) > 1:
                notes.append(f"Domain {name} mixes alphabets ({', '.join(sorted(scripts))}).")
        return ComparisonResult(DIFFERENT, "The codes lead to DIFFERENT websites.", notes)


# ======================================================================
# DATABASE
# ======================================================================
@dataclass
class ScanRecord:
    id: int
    scanned_at: str
    source_file: str
    kind: str
    content: str
    verdict: str
    notes: str = ""


class ScanRepository:
    """All SQL lives here; the rest of the app never writes queries."""

    def __init__(self, db_path: str | Path = DB_FILE):
        self._path = str(db_path)
        self._create_table()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path)

    def _create_table(self) -> None:
        with closing(self._connect()) as con, con:
            con.execute("""CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                source_file TEXT NOT NULL,
                kind TEXT NOT NULL,
                content TEXT NOT NULL,
                verdict TEXT NOT NULL,
                notes TEXT DEFAULT '')""")

    # Create
    def add(self, source_file: str, kind: str, content: str,
            verdict: str, notes: str = "") -> int:
        with closing(self._connect()) as con, con:
            cur = con.execute(
                "INSERT INTO scans (scanned_at, source_file, kind, content, verdict, notes) "
                "VALUES (?,?,?,?,?,?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source_file,
                 kind, content, verdict, notes))
            return cur.lastrowid

    # Read
    def all(self) -> list[ScanRecord]:
        with closing(self._connect()) as con:
            rows = con.execute("SELECT id, scanned_at, source_file, kind, content, verdict, notes "
                               "FROM scans ORDER BY id DESC").fetchall()
        return [ScanRecord(*r) for r in rows]

    def get(self, scan_id: int) -> ScanRecord | None:
        with closing(self._connect()) as con:
            row = con.execute("SELECT id, scanned_at, source_file, kind, content, verdict, notes "
                              "FROM scans WHERE id=?", (scan_id,)).fetchone()
        return ScanRecord(*row) if row else None

    # Update
    def update_notes(self, scan_id: int, notes: str) -> bool:
        with closing(self._connect()) as con, con:
            return con.execute("UPDATE scans SET notes=? WHERE id=?",
                               (notes, scan_id)).rowcount > 0

    # Delete
    def delete(self, scan_id: int) -> bool:
        with closing(self._connect()) as con, con:
            return con.execute("DELETE FROM scans WHERE id=?", (scan_id,)).rowcount > 0

    def clear(self) -> None:
        with closing(self._connect()) as con, con:
            con.execute("DELETE FROM scans")


# ======================================================================
# SERVICE
# ======================================================================
@dataclass
class ScanResult:
    source_file: str
    payload: Payload
    reputation: ReputationResult | None = None   # only for links
    extra_warnings: list[str] = field(default_factory=list)


class ScanSenseService:
    def __init__(self, decoder: QRDecoder | None = None,
                 checker: ReputationChecker | None = None,
                 repository: ScanRepository | None = None,
                 comparer: QRComparer | None = None):
        self._decoder = decoder or OpenCVQRDecoder()
        self._checker = checker or ReputationChecker()
        self._repo = repository or ScanRepository()
        self._comparer = comparer or QRComparer()

    @property
    def repository(self) -> ScanRepository:
        return self._repo

    def decode(self, image_path: str) -> ScanResult:
        """Decode + classify (fast, offline)."""
        payload = parse_payload(self._decoder.decode(image_path))
        return ScanResult(image_path, payload)

    def check_reputation(self, result: ScanResult) -> ScanResult:
        """Slow step (network) - the GUI runs this in a background thread."""
        if isinstance(result.payload, UrlPayload):
            result.reputation = self._checker.evaluate(result.payload)
        return result

    def save(self, result: ScanResult) -> int:
        rep = result.reputation
        verdict = rep.headline if rep else "n/a (not a link)"
        notes = "; ".join(rep.warnings) if rep else ""
        return self._repo.add(result.source_file, result.payload.kind,
                              result.payload.raw, verdict, notes)

    def compare(self, a: ScanResult, b: ScanResult) -> ComparisonResult:
        return self._comparer.compare(a.payload, b.payload)




def make_demo_qr_files(folder: Path = APP_DIR) -> tuple[Path, Path]:
    """Create two look-alike QR images (example.com vs examp1e.com) for the demo."""
    pairs = (("demo_printed.png", "https://www.example.com/menu"),
             ("demo_sticker.png", "https://www.examp1e.com/menu"))   # 'l' -> '1'
    paths = []
    for name, text in pairs:
        img = cv2.QRCodeEncoder.create().encode(text)
        img = cv2.resize(img, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
        img = cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
        path = Path(folder) / name
        cv2.imencode(".png", img)[1].tofile(str(path))
        paths.append(path)
    return paths[0], paths[1]


# ======================================================================
# GUI
# ======================================================================
COLORS = {"ok": "#1b7f3b", "bad": "#b00020", "warn": "#b36b00", "info": "#444444",
          "domain_bg": "#fff3a3"}
FILETYPES = [("Images", "*.png *.jpg *.jpeg *.bmp *.webp *.gif"), ("All files", "*.*")]


class ResultPanel(ttk.Frame):
    """Reusable widget: image preview + inspection results for ONE QR code.

    Used three ways (Inspect tab, Compare slot A, Compare slot B), which is
    the reason it is a class - one definition, many instances.
    """

    def __init__(self, master, service: ScanSenseService, title: str, **kw):
        super().__init__(master, padding=6, **kw)
        self._service = service
        self._photo = None
        self.result: ScanResult | None = None
        self._token = 0  # ignores late replies from older scans

        ttk.Label(self, text=title, font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Button(self, text="Choose QR image…", command=self.choose_file).pack(anchor="w", pady=4)
        self._preview = ttk.Label(self, text="No image", anchor="center", relief="groove")
        self._preview.pack(fill="x", ipady=4)

        self._type_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self._type_var, font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(8, 0))

        self._text = tk.Text(self, height=9, width=48, wrap="word", state="disabled",
                             relief="flat", background=self.winfo_toplevel().cget("background"))
        self._text.pack(fill="both", expand=True, pady=4)
        for name, cfg in {"domain": dict(background=COLORS["domain_bg"], font=("Consolas", 11, "bold")),
                          "url": dict(font=("Consolas", 11)),
                          "ok": dict(foreground=COLORS["ok"], font=("Segoe UI", 11, "bold")),
                          "bad": dict(foreground=COLORS["bad"], font=("Segoe UI", 11, "bold")),
                          "warn": dict(foreground=COLORS["warn"]),
                          "info": dict(foreground=COLORS["info"]),
                          "label": dict(font=("Segoe UI", 10, "bold"))}.items():
            self._text.tag_configure(name, **cfg)

    # ---------- user actions ----------
    def choose_file(self) -> None:
        path = filedialog.askopenfilename(title="Select a photo of a QR code", filetypes=FILETYPES)
        if path:
            self.load(path)

    def load(self, path: str) -> None:
        self._token += 1
        token = self._token
        self.result = None
        self._show_preview(path)
        self._write_start()
        try:
            result = self._service.decode(path)
        except DecodeError as exc:
            self._type_var.set("Could not read QR code")
            self._append(str(exc) + "\n", "bad")
            return
        except Exception as exc:  # unexpected - never crash the GUI
            self._type_var.set("Unexpected error")
            self._append(f"{type(exc).__name__}: {exc}\n", "bad")
            return
        self.result = result
        self._render_payload(result)
        if isinstance(result.payload, UrlPayload):
            self._append("\nChecking website reputation…\n", "info")
            threading.Thread(target=self._reputation_worker, args=(result, token), daemon=True).start()
        else:
            self._service.save(result)

    def _reputation_worker(self, result: ScanResult, token: int) -> None:
        try:
            self._service.check_reputation(result)
        except Exception as exc:  # pragma: no cover
            result.extra_warnings.append(f"Reputation check failed: {exc}")
        self.after(0, self._reputation_done, result, token)

    def _reputation_done(self, result: ScanResult, token: int) -> None:
        if token != self._token:
            return
        self._render_payload(result)
        self._service.save(result)

    # ---------- rendering ----------
    def _show_preview(self, path: str) -> None:
        try:
            img = Image.open(path)
            img.thumbnail((170, 170))
            self._photo = ImageTk.PhotoImage(img)
            self._preview.configure(image=self._photo, text="")
        except Exception:
            self._preview.configure(image="", text="(cannot preview)")

    def _write_start(self) -> None:
        self._type_var.set("Reading…")
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")

    def _append(self, text: str, tag: str = "") -> None:
        self._text.configure(state="normal")
        self._text.insert("end", text, tag)
        self._text.configure(state="disabled")

    def _render_payload(self, result: ScanResult) -> None:
        p = result.payload
        self._type_var.set(f"This QR code contains: {p.kind}")
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")

        if isinstance(p, UrlPayload):
            before, dom, after = p.split_for_highlight()
            self._append("Destination:\n", "label")
            self._append(before, "url"); self._append(dom, "domain"); self._append(after + "\n\n", "url")
            self._append(f"Real domain:  ", "label"); self._append(p.registered_domain + "\n", "domain")
            if p.subdomain:
                self._append(f"Subdomain:  {p.subdomain}\n", "info")
        else:
            for label, value in p.details():
                self._append(f"{label}: ", "label"); self._append(f"{value}\n")

        rep = result.reputation
        if rep:
            self._append("\n")
            tag = {"FLAGGED": "bad", "NO_KNOWN_THREAT": "ok"}.get(rep.verdict, "warn")
            self._append(f"Reputation: {rep.headline}\n", tag)
            for t in rep.threats:
                self._append(f"  • {t}\n", "bad")
            if rep.note:
                self._append(rep.note + "\n", "info")
            for w in rep.warnings:
                self._append(f"⚠ {w}\n", "warn")
        for w in result.extra_warnings:
            self._append(f"⚠ {w}\n", "warn")


class CompareTab(ttk.Frame):
    def __init__(self, master, service: ScanSenseService):
        super().__init__(master, padding=6)
        self._service = service
        ttk.Button(self, text="Do these lead to the same place?", command=self.compare).pack(pady=4)
        self._verdict = tk.StringVar()
        self._label = ttk.Label(self, textvariable=self._verdict, font=("Segoe UI", 13, "bold"))
        self._label.pack()
        self._notes = tk.StringVar()
        ttk.Label(self, textvariable=self._notes, wraplength=760, justify="left").pack(pady=2)
        panels = ttk.Frame(self); panels.pack(fill="both", expand=True)
        self.a = ResultPanel(panels, service, "Code A (e.g. printed)")
        self.b = ResultPanel(panels, service, "Code B (e.g. sticker)")
        self.a.pack(side="left", fill="both", expand=True)
        self.b.pack(side="left", fill="both", expand=True)

    def compare(self) -> None:
        if not (self.a.result and self.b.result):
            messagebox.showinfo("ScanSense", "Please load a readable QR image into BOTH slots first.")
            return
        res = self._service.compare(self.a.result, self.b.result)
        colour = {SAME: COLORS["ok"], SAME_SITE: COLORS["warn"], DIFFERENT: COLORS["bad"]}[res.outcome]
        self._label.configure(foreground=colour)
        self._verdict.set(res.summary)
        self._notes.set("\n".join(res.notes))


class HistoryTab(ttk.Frame):
    COLS = ("id", "scanned_at", "kind", "verdict", "content")

    def __init__(self, master, service: ScanSenseService):
        super().__init__(master, padding=6)
        self._repo = service.repository
        bar = ttk.Frame(self); bar.pack(fill="x")
        for text, cmd in (("Refresh", self.refresh), ("Edit note", self.edit_note),
                          ("Delete selected", self.delete_selected), ("Clear all", self.clear_all)):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=2)
        self._tree = ttk.Treeview(self, columns=self.COLS, show="headings", height=14)
        widths = (40, 140, 130, 170, 420)
        for c, w in zip(self.COLS, widths):
            self._tree.heading(c, text=c.replace("_", " ").title())
            self._tree.column(c, width=w, anchor="w")
        self._tree.pack(fill="both", expand=True, pady=6)
        self._note_var = tk.StringVar()
        ttk.Label(self, textvariable=self._note_var, wraplength=760).pack(anchor="w")
        self._tree.bind("<<TreeviewSelect>>", self._show_note)
        self.refresh()

    def _selected_id(self) -> int | None:
        sel = self._tree.selection()
        return int(self._tree.item(sel[0], "values")[0]) if sel else None

    def refresh(self) -> None:
        self._tree.delete(*self._tree.get_children())
        for r in self._repo.all():
            self._tree.insert("", "end", values=(r.id, r.scanned_at, r.kind, r.verdict, r.content))

    def _show_note(self, _evt=None) -> None:
        sid = self._selected_id()
        rec = self._repo.get(sid) if sid else None
        self._note_var.set(f"Notes: {rec.notes}" if rec else "")

    def edit_note(self) -> None:
        sid = self._selected_id()
        if sid is None:
            return messagebox.showinfo("ScanSense", "Select a row first.")
        rec = self._repo.get(sid)
        new = simpledialog.askstring("Edit note", "Note:", initialvalue=rec.notes, parent=self)
        if new is not None:
            self._repo.update_notes(sid, new)
            self.refresh()

    def delete_selected(self) -> None:
        sid = self._selected_id()
        if sid is not None and self._repo.delete(sid):
            self.refresh()

    def clear_all(self) -> None:
        if messagebox.askyesno("ScanSense", "Delete the whole scan history?"):
            self._repo.clear()
            self.refresh()


class ScanSenseApp(tk.Tk):
    def __init__(self, service: ScanSenseService | None = None):
        super().__init__()
        self.title("ScanSense - see where a QR code leads before you open it")
        self.geometry("900x620")
        self.minsize(800, 560)
        self._service = service or ScanSenseService()
        # Status bar + demo button sit at the TOP so they are always visible
        key_ok = self._service._checker._online.configured  # noqa: SLF001
        status = ("Reputation API: connected" if key_ok else
                  "Reputation API: no key set - links are checked with offline red-flag rules only")
        foot = ttk.Frame(self)
        foot.pack(side="top", fill="x", padx=8, pady=4)
        ttk.Button(foot, text="Create demo QR codes", command=self._make_demo).pack(side="left")
        ttk.Label(foot, text=status, foreground=COLORS["info"]).pack(side="left", padx=10)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=6)
        inspect = ResultPanel(nb, self._service, "Inspect one QR code")
        history = HistoryTab(nb, self._service)
        nb.add(inspect, text="  Inspect  ")
        nb.add(CompareTab(nb, self._service), text="  Compare two codes  ")
        nb.add(history, text="  History  ")
        nb.bind("<<NotebookTabChanged>>", lambda e: history.refresh())

    def _make_demo(self) -> None:
        try:
            a, b = make_demo_qr_files()
            messagebox.showinfo("ScanSense", f"Created:\n{a}\n{b}\n\nLoad them in the Compare tab.")
        except Exception as exc:
            messagebox.showerror("ScanSense", f"Could not create demo files: {exc}")



if __name__ == "__main__":
    ScanSenseApp().mainloop()
