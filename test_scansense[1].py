"""Run with:  py -m unittest -v test_scansense"""
import json
import os
import tempfile
import unittest
from unittest import mock

import cv2
import numpy as np

from scansense_app import (
    DIFFERENT, FLAGGED, NO_THREAT, SAME, SAME_SITE, UNCHECKED,
    ContactPayload, DecodeError, HeuristicService, OpenCVQRDecoder, OtherUriPayload,
    QRComparer, ReputationChecker, ReputationError, ReputationService,
    SafeBrowsingService, ScanRepository, ScanSenseService, TextPayload,
    UrlPayload, WifiPayload, parse_payload)


def make_qr_file(text: str, folder: str, name: str = "qr.png") -> str:
    """Generate a QR image with OpenCV's encoder (no extra library needed)."""
    img = cv2.QRCodeEncoder.create().encode(text)
    img = cv2.resize(img, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    img = cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    path = os.path.join(folder, name)
    cv2.imwrite(path, img)
    return path


class FakeService(ReputationService):
    def __init__(self, result=None, error=None):
        self.result, self.error = result or [], error

    def check(self, payload):
        if self.error:
            raise self.error
        return self.result


class TestParsing(unittest.TestCase):
    def test_url(self):
        p = parse_payload("https://login.paypal.com/signin?x=1")
        self.assertIsInstance(p, UrlPayload)
        self.assertEqual(p.registered_domain, "paypal.com")
        self.assertEqual(p.subdomain, "login")

    def test_two_part_suffix(self):
        self.assertEqual(parse_payload("https://shop.example.co.uk/a").registered_domain, "example.co.uk")

    def test_highlight_split(self):
        before, dom, after = parse_payload("https://a.evil.com/pay").split_for_highlight()
        self.assertEqual((before, dom, after), ("https://a.", "evil.com", "/pay"))

    def test_wifi(self):
        p = parse_payload(r"WIFI:T:WPA;S:Cafe\;Guest;P:secret;;")
        self.assertIsInstance(p, WifiPayload)
        self.assertEqual(p.ssid, "Cafe;Guest")
        self.assertNotIn("secret", str(p.details()))

    def test_vcard_and_mecard(self):
        v = parse_payload("BEGIN:VCARD\nFN:Ali Khan\nTEL:+971500000000\nEND:VCARD")
        m = parse_payload("MECARD:N:Khan,Ali;TEL:123;;")
        self.assertIsInstance(v, ContactPayload)
        self.assertIsInstance(m, ContactPayload)
        self.assertIn(("Name", "Ali Khan"), v.details())

    def test_other_uri_and_text(self):
        self.assertIsInstance(parse_payload("tel:+97150"), OtherUriPayload)
        self.assertIsInstance(parse_payload("hello world"), TextPayload)

    def test_schemeless_domain(self):
        self.assertIsInstance(parse_payload("example.com/menu"), UrlPayload)

    def test_polymorphic_details(self):
        for raw in ("https://a.com", "WIFI:S:x;;", "hello", "tel:1"):
            self.assertTrue(parse_payload(raw).details())


class TestHeuristics(unittest.TestCase):
    def check(self, url):
        return HeuristicService().check(parse_payload(url))

    def test_ip(self):
        self.assertTrue(any("IP" in w for w in self.check("http://192.168.0.1/x")))

    def test_shortener_and_http(self):
        w = " ".join(self.check("http://bit.ly/abc"))
        self.assertIn("shortener", w)
        self.assertIn("not encrypted", w)

    def test_clean_https(self):
        self.assertEqual(self.check("https://www.example.com/menu"), [])


class TestReputation(unittest.TestCase):
    URL = parse_payload("https://example.com")

    def test_flagged(self):
        r = ReputationChecker(FakeService(["Phishing"])).evaluate(self.URL)
        self.assertEqual(r.verdict, FLAGGED)

    def test_no_threat_wording(self):
        r = ReputationChecker(FakeService([])).evaluate(self.URL)
        self.assertEqual(r.verdict, NO_THREAT)
        self.assertEqual(r.headline, "No known threat found")
        self.assertNotIn("safe.", r.headline.lower())

    def test_api_error_is_unchecked_not_safe(self):
        r = ReputationChecker(FakeService(error=ReputationError("offline"))).evaluate(self.URL)
        self.assertEqual(r.verdict, UNCHECKED)

    def test_no_key(self):
        with mock.patch("scansense_app.load_api_key", return_value=""):
            self.assertFalse(SafeBrowsingService().configured)
            r = ReputationChecker(SafeBrowsingService("")).evaluate(self.URL)
            self.assertEqual(r.verdict, UNCHECKED)

    def test_parse_api_response(self):
        data = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}, {"threatType": "MALWARE"}]}
        self.assertEqual(SafeBrowsingService.parse_response(data),
                         ["Malware", "Phishing / social engineering"])
        self.assertEqual(SafeBrowsingService.parse_response({}), [])

    def test_request_body(self):
        body = SafeBrowsingService("k")._build_request_body("https://x.com")
        self.assertEqual(body["threatInfo"]["threatEntries"][0]["url"], "https://x.com")
        json.dumps(body)

    def test_http_error_mapped(self):
        import urllib.error
        err = urllib.error.HTTPError("u", 403, "Forbidden", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(ReputationError):
                SafeBrowsingService("bad").check(self.URL)


class TestComparer(unittest.TestCase):
    cmp = QRComparer()

    def c(self, a, b):
        return self.cmp.compare(parse_payload(a), parse_payload(b))

    def test_same(self):
        self.assertEqual(self.c("https://www.a.com/x/", "http://a.com/x").outcome, SAME)

    def test_same_site(self):
        self.assertEqual(self.c("https://a.com/x", "https://a.com/y").outcome, SAME_SITE)

    def test_lookalike(self):
        r = self.c("https://example.com/menu", "https://examp1e.com/menu")
        self.assertEqual(r.outcome, DIFFERENT)
        self.assertTrue(any("look-alike" in n for n in r.notes))

    def test_mixed_script(self):
        r = self.c("https://apple.com", "https://аpple.com")  # Cyrillic а
        self.assertEqual(r.outcome, DIFFERENT)
        self.assertTrue(any("alphabet" in n or "non-standard" in n for n in r.notes))

    def test_different_types(self):
        self.assertEqual(self.c("https://a.com", "hello").outcome, DIFFERENT)


class TestDatabase(unittest.TestCase):
    def test_crud(self):
        with tempfile.TemporaryDirectory() as d:
            repo = ScanRepository(os.path.join(d, "t.db"))
            sid = repo.add("f.png", "Website link", "https://a.com", "No known threat found")
            self.assertEqual(repo.get(sid).content, "https://a.com")
            self.assertTrue(repo.update_notes(sid, "checked"))
            self.assertEqual(repo.all()[0].notes, "checked")
            self.assertTrue(repo.delete(sid))
            self.assertFalse(repo.delete(sid))
            self.assertIsNone(repo.get(sid))

    def test_sql_injection_safe(self):
        with tempfile.TemporaryDirectory() as d:
            repo = ScanRepository(os.path.join(d, "t.db"))
            repo.add("f", "k", "x'); DROP TABLE scans;--", "v")
            self.assertEqual(len(repo.all()), 1)


class TestDecoderAndService(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = make_qr_file("https://example.com/a", d)
            self.assertEqual(OpenCVQRDecoder().decode(path), "https://example.com/a")

    def test_errors(self):
        dec = OpenCVQRDecoder()
        with self.assertRaises(DecodeError):
            dec.decode("/no/such/file.png")
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "x.png")
            with open(bad, "w") as fh:
                fh.write("not an image")
            with self.assertRaises(DecodeError):
                dec.decode(bad)
            blank = os.path.join(d, "blank.png")
            cv2.imwrite(blank, 255 * np.ones((200, 200), "uint8"))
            with self.assertRaises(DecodeError):
                dec.decode(blank)

    def test_full_flow_and_compare(self):
        with tempfile.TemporaryDirectory() as d:
            svc = ScanSenseService(
                checker=ReputationChecker(FakeService([])),
                repository=ScanRepository(os.path.join(d, "t.db")))
            a = svc.check_reputation(svc.decode(make_qr_file("https://example.com/menu", d, "a.png")))
            b = svc.check_reputation(svc.decode(make_qr_file("https://examp1e.com/menu", d, "b.png")))
            self.assertEqual(a.reputation.headline, "No known threat found")
            svc.save(a)
            self.assertEqual(len(svc.repository.all()), 1)
            self.assertEqual(svc.compare(a, b).outcome, DIFFERENT)


if __name__ == "__main__":
    unittest.main()
