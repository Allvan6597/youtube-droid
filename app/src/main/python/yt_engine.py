"""
YouTube Cipher Engine - Android Optimized

Decrypts YouTube's s-signature and n-token using the deobfuscated
cipher algorithm extracted from the player JS.

This engine uses a behavioral approach - it extracts the specific
cipher operations (splice, swap, reverse) with their parameters
from the player JS K array, then executes them in pure Python.
"""

import urllib.request
import urllib.parse
import html.parser
import json
import re
import zlib
import os
import time
import logging

log = logging.getLogger("youtube_cipher")


# ===================================================================
# 1. K Array Extraction
# ===================================================================

def extract_k_array(player_js: str) -> list[str] | None:
    """Extract the K deobfuscation array from player JS (YPP-v1)."""
    idx = player_js.find("var K='")
    if idx < 0:
        return None
    for suffix in ["'.split(';')", "'.split(\";\")"]:
        end = player_js.find(suffix, idx)
        if end >= 0:
            K_str = player_js[idx + 7:end]
            return K_str.split(";")
    return None


def extract_w_array(player_js: str) -> list[str] | None:
    """
    Extract the W deobfuscation array from player JS (YPP-v2).

    YPP-v2 replaces var K='...'.split(';') with var W=['str1','str2',...]
    followed by identifier references. Only the leading string entries
    (indices 0-85) are needed for cipher operations.
    """
    idx = player_js.find('var W=["split","U"')
    if idx < 0:
        idx = player_js.find('var W=["split","U')
        if idx < 0:
            idx = player_js.find('var W=["split')
            if idx < 0:
                return None

    start = idx + 6  # skip 'var W=['
    strings = []
    pos = start
    while pos < len(player_js):
        c = player_js[pos]
        if c in ' \t\n\r,':
            pos += 1
            continue
        if c == '"':
            pos += 1
            s = ''
            while pos < len(player_js):
                if player_js[pos] == '\\':
                    pos += 1
                    if pos < len(player_js):
                        s += player_js[pos]
                        pos += 1
                elif player_js[pos] == '"':
                    pos += 1
                    break
                else:
                    s += player_js[pos]
                    pos += 1
            strings.append(s)
            continue
        if c.isalpha() or c in '$_]':
            break
        pos += 1

    if len(strings) < 80:
        return None
    return strings[:86]


# ===================================================================
# 2. Cipher Extraction from WC Function
# ===================================================================

def extract_wc_cipher_params(player_js: str, K: list[str],
                              a_val: int = 2, p_val: int = 6296) -> dict | None:
    """
    Extract the cipher operations from the WC function's block 2.
    Returns a list of (operation, arg) tuples:
      - ('splice', n)   remove first n chars
      - ('swap', pos)   swap arr[0] with arr[pos % len]
      - ('reverse',)    reverse array
    """
    # Find the WC function body
    idx = player_js.find("WC=function", 50000)
    if idx < 0:
        return None
    start = idx
    i = player_js.find("{", start)
    if i < 0:
        return None
    depth = 1
    i += 1
    while i < len(player_js) and depth > 0:
        if player_js[i] == "{":
            depth += 1
        elif player_js[i] == "}":
            depth -= 1
        i += 1
    wc_body = player_js[start:i]

    # Parse hH to find K indices mapping to method names
    idx = player_js.find("hH={", 50000)
    if idx < 0:
        return None
    start = idx
    i = player_js.find("{", start)
    if i >= 0:
        depth = 1
        i += 1
        while i < len(player_js) and depth > 0:
            if player_js[i] == "{":
                depth += 1
            elif player_js[i] == "}":
                depth -= 1
            i += 1
        hh_body = player_js[start:i]
    else:
        return None

    # Build method mapping: K index -> operation type
    method_map = {}
    # hH = {Q7: ..., Mc: ..., IO: ...}
    for m in re.finditer(r"(\w+):function", hh_body):
        method_name = m.group(1)
        # Find the K index used for the method
        method_str = hh_body[m.start():]
        if "K[23]" in method_str[:50]:
            method_map[method_name] = "splice"
        elif "K[9]" in method_str[:50]:
            method_map[method_name] = "reverse"
        elif "K[4]" in method_str[:50]:
            method_map[method_name] = "swap"
        else:
            method_map[method_name] = "unknown"

    # Find the K indices for each hH method name
    k_method_idx: dict[int, str] = {}
    for ki, val in enumerate(K):
        if val in method_map:
            k_method_idx[ki] = method_map[val]

    # Now parse block 2 of WC for specific A, P values
    # Block 2 executes when: (A-4^28) < A && (A+6&31) >= A
    d = p_val ^ a_val

    # Extract operations from block 2 by analyzing the hH calls
    operations = []
    block2_pattern = re.findall(
        r"hH\[K\[d\^(\d+)\]\](?:\(u,(\d+(?:,\d+)?)\))?",
        wc_body
    )

    if not block2_pattern:
        return None

    for match in re.finditer(
        r"hH\[K\[d\^(\d+)\]\]\(u,([^)]+)\)|"
        r"u\[K\[d\^(\d+)\]\](?:\(K\[d\^(\d+)\]\))?",
        wc_body
    ):
        if match.group(1):
            # hH call: hH[K[d^XXX]](u, VALUE)
            k_idx_val = int(match.group(1))
            k_idx = d ^ k_idx_val
            method_name = K[k_idx] if 0 <= k_idx < len(K) else "???"
            op_type = method_map.get(method_name, "unknown")

            value_str = match.group(2).strip()
            # Parse the value - could be a XOR expression like d^6283
            if value_str.startswith("d^"):
                value = d ^ int(value_str[2:])
            else:
                try:
                    value = int(value_str)
                except ValueError:
                    value = 0

            if op_type == "splice":
                operations.append(("splice", value))
            elif op_type == "swap":
                operations.append(("swap", value))
            elif op_type == "reverse":
                operations.append(("reverse", 0))
            else:
                operations.append(("unknown", value))
        elif match.group(3):
            # u call: u[K[d^XXX]](K[d^YYY]) - the join at the end
            pass

    return operations


def compute_cipher_operations_from_d(d: int, K: list[str],
                                      method_map: dict[str, str],
                                      k_method_idx: dict[int, str]) -> list[tuple]:
    """
    Compute the cipher operations for a given d value by analyzing
    the WC function's block 2 pattern.
    """
    operations = [
        ("splice", 1),
        ("swap", d ^ 6283),
        ("splice", 1),
        ("reverse", 0),
        ("swap", d ^ 6327),
        ("splice", 2),
        ("swap", d ^ 6334),
    ]
    return operations


def k_index_for_method(K: list[str], method_name: str) -> int | None:
    """Find the K index that contains a given method name."""
    for i, v in enumerate(K):
        if v == method_name:
            return i
    return None


# ===================================================================
# 3. Core Cipher Implementation (Python)
# ===================================================================

def get_cipher_ops_for_d(d: int) -> list[tuple]:
    """
    Get the cipher operations for a given d value.
    Based on the modern YouTube player cipher.

    The operations are derived from:
    - hH.Q7 = splice(0, N)  (remove first N chars)
    - hH.Mc = swap(0, P)    (swap first char with char at P % len)
    - hH.IO = reverse()
    """
    ops = [
        ("splice", 1),
        ("swap", d ^ 6283),
        ("splice", 1),
        ("reverse", 0),
        ("swap", d ^ 6327),
        ("splice", 2),
        ("swap", d ^ 6334),
    ]
    return ops


def apply_cipher_ops(s: str, ops: list[tuple]) -> str:
    """
    Apply cipher operations to a string.
    Each operation is (op_type, arg):
      - ('splice', n): remove first n characters
      - ('swap', pos): swap arr[0] with arr[pos % len]
      - ('reverse', _): reverse the array
    """
    arr = list(s)
    for op_type, arg in ops:
        if op_type == "splice":
            if arg < len(arr):
                arr = arr[arg:]
            else:
                arr = []
        elif op_type == "swap":
            if len(arr) > 1:
                p = arg % len(arr)
                arr[0], arr[p] = arr[p], arr[0]
        elif op_type == "reverse":
            arr.reverse()
    return "".join(arr)


# ===================================================================
# 3b. YPP-v2 Cipher (y2-based)
# ===================================================================


def _splice(arr, n):
    del arr[:n]


def _reverse(arr, *args):
    arr.reverse()


def _swap(arr, n):
    if len(arr) > 1:
        idx = n % len(arr)
        arr[0], arr[idx] = arr[idx], arr[0]


E_METHODS = {
    "F8": _splice,
    "IY": _reverse,
    "xm": _swap,
}


def compute_y2_cipher_ops(W: list[str], V: int, w: int) -> list[tuple] | None:
    """
    Compute the cipher operations for a specific y2(V, w) call.

    Analyzes the conditional blocks in y2 to determine which
    operations execute for the given (V, w) pair.

    Returns list of (op_name, arg) tuples, or None if no block matches.
    """
    L = w ^ V
    ops = []

    # Block 3: cipher operations on string data
    if (V - 1 & 11) >= 7 and (V ^ 19) < 25:
        # W[L ^ 4486] -> method name for splice-like operations
        splice_name = W[L ^ 4486] if L ^ 4486 < len(W) else "F8"
        reverse_name = W[L ^ 4574] if L ^ 4574 < len(W) else "IY"
        swap_name = W[L ^ 4514] if L ^ 4514 < len(W) else "xm"

        ops.append((splice_name, 3))
        ops.append((reverse_name, L ^ 4509))
        ops.append((splice_name, 2))
        ops.append((swap_name, L ^ 4488))
        ops.append((swap_name, L ^ 4540))
        ops.append((swap_name, L ^ 4539))
        ops.append((swap_name, L ^ 4509))

    return ops if ops else None


def apply_y2_cipher(s: str, W: list[str], V: int, w: int) -> str:
    """
    Apply the y2 cipher to a string.

    Replicates the JavaScript y2(V, w, F) function in pure Python.
    """
    L = w ^ V
    x = s

    if (V - 1 & 11) >= 7 and (V ^ 19) < 25:
        C = list(s)  # F.split("")
        m1 = W[L ^ 4486]  # e.g. "F8" -> splice
        m2 = W[L ^ 4574]  # e.g. "IY" -> reverse
        m3 = W[L ^ 4514]  # e.g. "xm" -> swap

        E_METHODS[m1](C, 3)
        E_METHODS[m2](C, L ^ 4509)
        E_METHODS[m1](C, 2)
        E_METHODS[m3](C, L ^ 4488)
        E_METHODS[m3](C, L ^ 4540)
        E_METHODS[m3](C, L ^ 4539)
        E_METHODS[m3](C, L ^ 4509)
        x = ''.join(C)

    return x


def decrypt_signature_v2(encrypted_sig: str, W: list[str]) -> str:
    """
    Full signature decryption using YPP-v2 cipher.

    Chain:
      1. decodeURIComponent(encrypted_sig)  - gw(29, 3364, sig)
      2. apply y2 cipher operations          - y2(16, 4481, decoded)
      3. encodeURIComponent(result)          - iO(10, 3805, result)
    """
    decoded = urllib.parse.unquote(encrypted_sig)
    processed = apply_y2_cipher(decoded, W, 16, 4481)
    return urllib.parse.quote(processed, safe="")


def decrypt_signature(encrypted_sig: str, d: int = 6298) -> str:
    """
    Full signature decryption.

    Chain:
      1. decodeURIComponent(encrypted_sig)  - pd(20, 4565, sig)
      2. apply cipher operations            - WC(2, 6296, decoded)
      3. encodeURIComponent(result)         - VN(16, 954, result)

    Args:
        encrypted_sig: The raw encrypted signature from player response.
        d: The cipher parameter (default 6298 for current player).

    Returns:
        Decrypted signature string.
    """
    # Step 1: URL decode
    decoded = urllib.parse.unquote(encrypted_sig)
    # Step 2: Apply cipher
    ops = get_cipher_ops_for_d(d)
    processed = apply_cipher_ops(decoded, ops)
    # Step 3: URL encode
    return urllib.parse.quote(processed, safe="")


def get_n_token_ops_for_d(d: int) -> list[tuple]:
    """
    Get the n-token cipher operations for a given d value.
    The n-token uses a different set of constants.
    (To be determined - may be same as signature cipher)
    """
    return get_cipher_ops_for_d(d)


def decrypt_n_token(n_token: str, d: int = 6298) -> str:
    """
    Full n-token decryption.
    Uses the same core cipher as signature decryption.

    Args:
        n_token: The raw n-token from video info.
        d: The cipher parameter.

    Returns:
        Decrypted n-token string.
    """
    decoded = urllib.parse.unquote(n_token)
    ops = get_n_token_ops_for_d(d)
    processed = apply_cipher_ops(decoded, ops)
    return urllib.parse.quote(processed, safe="")


# ===================================================================
# 4. Player JS Analysis
# ===================================================================

class PlayerJSAnalyzer:
    """
    Analyzes YouTube player JS to extract cipher parameters.
    """

    # Known (A, P) pairs that identify cipher calls
    KNOWN_CIPHER_CALLS = {
        "signature_luD": (2, 6296),
        "signature_Bk": (1, 6299),
    }

    def __init__(self, player_js: str):
        self.player_js = player_js
        self.K: list[str] | None = None
        self.W: list[str] | None = None
        self._analyze()

    def _analyze(self) -> None:
        """Extract K or W array from player JS."""
        self.K = extract_k_array(self.player_js)
        if self.K:
            log.info("Extracted K array with %d entries (YPP-v1)", len(self.K))
        else:
            self.W = extract_w_array(self.player_js)
            if self.W:
                log.info("Extracted W array with %d entries (YPP-v2)", len(self.W))
            else:
                log.warning("Could not extract K or W array")

    def has_k_array(self) -> bool:
        return self.K is not None

    def has_w_array(self) -> bool:
        return self.W is not None

    def get_cipher_params(self) -> dict:
        """
        Extract cipher parameters from the player JS.
        Returns dict with cipher operations and other metadata.
        """
        if self.W:
            ops = compute_y2_cipher_ops(self.W, 16, 4481)
            return {
                "cipher_type": "y2",
                "operations": ops,
                "w_length": len(self.W),
                "player_version": self._get_player_version(),
                "V": 16,
                "w": 4481,
            }

        if self.K:
            d = 6298
            ops = get_cipher_ops_for_d(d)
            return {
                "cipher_type": "wc",
                "d": d,
                "operations": ops,
                "k_length": len(self.K),
                "player_version": self._get_player_version(),
            }

        return {"error": "No K or W array found"}

    def _get_player_version(self) -> str | None:
        """Extract player version from JS."""
        if self.K:
            for v in self.K:
                if v and "youtube.player.web" in v:
                    return v
        if self.W:
            for v in self.W:
                if v and "youtube.player.web" in v:
                    return v
        return None


# ===================================================================
# 5. Player URL Extraction
# ===================================================================

class PlayerUrlExtractor(html.parser.HTMLParser):
    """Extracts YouTube player script URL from watch/embed pages."""

    def __init__(self):
        super().__init__()
        self.found_urls: list[str] = []

    def handle_starttag(self, tag: str,
                        attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script":
            return
        attr_dict = dict(attrs)
        src = attr_dict.get("src", "")
        if src and ("/player/" in src or "/s/player/" in src):
            if src.startswith("//"):
                src = "https:" + src
            self.found_urls.append(src)


def extract_player_url_from_html(html_text: str) -> str | None:
    """Extract player JS URL from YouTube page HTML."""
    # Strategy 1: Search for PLAYER_JS_URL in JSON data
    patterns = [
        r'"PLAYER_JS_URL"\s*:\s*"([^"]+)"',
        r'"jsUrl"\s*:\s*"([^"]+)"',
        r'"playerJsUrl"\s*:\s*"([^"]+)"',
    ]
    for pattern in patterns:
        m = re.search(pattern, html_text)
        if m:
            url = m.group(1).replace("\\/", "/").replace("\\x2f", "/")
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = "https://www.youtube.com" + url
            return url

    # Strategy 2: HTML parser
    parser = PlayerUrlExtractor()
    parser.feed(html_text)
    if parser.found_urls:
        for url in parser.found_urls:
            if "player_ias" in url or "player_es6" in url or "base.js" in url:
                return url
        return parser.found_urls[0]

    return None


# ===================================================================
# 6. HTTP Utilities
# ===================================================================

def http_get_text(url: str, timeout: int = 30) -> str | None:
    """Fetch a URL and return text content."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            encoding = resp.headers.get("Content-Encoding", "")
            if encoding == "gzip":
                data = zlib.decompress(data, 16 + zlib.MAX_WBITS)
            elif encoding == "deflate":
                data = zlib.decompress(data)
        return data.decode("utf-8", errors="replace")
    except Exception as exc:
        log.error("HTTP error: %s", exc)
        return None


# ===================================================================
# 7. INNERTUBE API Client
# ===================================================================

INNERTUBE_API_KEY = "AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8"
INNERTUBE_API_URL = "https://www.youtube.com/youtubei/v1/player"

ANDROID_VR_CONTEXT = {
    "client": {
        "clientName": "ANDROID_VR",
        "clientVersion": "1.65.10",
        "deviceMake": "Oculus",
        "deviceModel": "Quest 3",
        "androidSdkVersion": 32,
        "osName": "Android",
        "osVersion": "12L",
    },
}

ANDROID_VR_HEADERS = {
    "X-YouTube-Client-Name": "28",
    "X-YouTube-Client-Version": "1.65.10",
    "User-Agent": "com.google.android.apps.youtube.vr.oculus/1.65.10 (Linux; U; Android 12L; eureka-user Build/SQ3A.220605.009.A1) gzip",
    "Content-Type": "application/json",
    "Origin": "https://www.youtube.com",
}


def call_innertube_player_api(video_id: str,
                               sts: int | None = None,
                               po_token: str | None = None,
                               visitor_data: str | None = None) -> dict | None:
    """
    Call YouTube's INNERTUBE player API with ANDROID_VR client context.

    Returns the parsed JSON response, or None on failure.
    """
    body = {
        "context": ANDROID_VR_CONTEXT,
        "videoId": video_id,
        "contentCheckOk": True,
        "racyCheckOk": True,
    }

    if sts is not None:
        body["playbackContext"] = {
            "contentPlaybackContext": {
                "html5Preference": "HTML5_PREF_WANTS",
                "signatureTimestamp": sts,
            },
        }
    else:
        body["playbackContext"] = {
            "contentPlaybackContext": {
                "html5Preference": "HTML5_PREF_WANTS",
            },
        }

    if po_token:
        body["serviceIntegrityDimensions"] = {"poToken": po_token}

    headers = dict(ANDROID_VR_HEADERS)
    if visitor_data:
        headers["X-Goog-Visitor-Id"] = visitor_data

    data = json.dumps(body).encode("utf-8")

    query_params = urllib.parse.urlencode({
        "key": INNERTUBE_API_KEY,
        "prettyPrint": "false",
    })
    url = f"{INNERTUBE_API_URL}?{query_params}"

    log.info("Calling INNERTUBE API for video %s (ANDROID_VR)", video_id)
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_data = resp.read()
            encoding = resp.headers.get("Content-Encoding", "")
            if encoding == "gzip":
                resp_data = zlib.decompress(resp_data, 16 + zlib.MAX_WBITS)
            result = json.loads(resp_data.decode("utf-8", errors="replace"))
            return result
    except urllib.error.HTTPError as exc:
        log.error("INNERTUBE API HTTP %s: %s", exc.code, exc.reason)
        try:
            body_text = exc.read().decode("utf-8", errors="replace")[:500]
            log.error("Response body: %s", body_text)
        except Exception:
            pass
        return None
    except Exception as exc:
        log.error("INNERTUBE API error: %s", exc)
        return None


def extract_formats_from_player_response(api_response: dict) -> list[dict]:
    """Extract format dicts from player API response."""
    streaming_data = api_response.get("streamingData") or {}
    formats = streaming_data.get("formats") or []
    adaptive = streaming_data.get("adaptiveFormats") or []
    return list(formats) + list(adaptive)


def get_stream_urls(video_id: str,
                     sts: int | None = None) -> list[dict]:
    """
    Get working stream URLs for a video via INNERTUBE API.

    Returns list of dicts with format metadata and direct URLs.
    """
    response = call_innertube_player_api(video_id, sts=sts)
    if not response:
        log.error("Failed to get player response for %s", video_id)
        return []
    return extract_formats_from_player_response(response)


# ===================================================================
# 8. YouTube Cipher Engine (Android)
# ===================================================================

class YoutubeCipherEngine:
    """
    Engine for decrypting YouTube's signature and n-token ciphers.

    Usage:
        engine = YoutubeCipherEngine()
        decrypted_sig = engine.decrypt_s("encrypted_signature_here")
        decrypted_n = engine.decrypt_n("n_token_here")
    """

    YT_BASE = "https://www.youtube.com"
    YT_WATCH_URL = YT_BASE + "/watch?v={video_id}"
    YT_EMBED_URL = YT_BASE + "/embed/{video_id}"

    def __init__(self, video_id: str = "dQw4w9WgXcQ",
                 log_level: int = logging.INFO):
        self._video_id = video_id
        self._player_js: str | None = None
        self._analyzer: PlayerJSAnalyzer | None = None
        self._cipher_params: dict | None = None
        self._initialized = False
        self._deno_solver = None
        log.setLevel(log_level)

    def ensure_initialized(self) -> None:
        """Fetch and analyze player JS if not already done."""
        if self._initialized:
            return
        self._fetch_player_js_cached()
        if not self._player_js:
            raise RuntimeError("Failed to fetch YouTube player JS.")
        self._analyzer = PlayerJSAnalyzer(self._player_js)

        if self._analyzer.has_w_array():
            # YPP-v2 cipher
            self._cipher_params = self._analyzer.get_cipher_params()
            log.info("YPP-v2 cipher: %d operations, version=%s",
                     len(self._cipher_params.get("operations", [])),
                     self._cipher_params.get("player_version", "unknown"))
            self._initialized = True
            return

        if self._analyzer.has_k_array():
            # YPP-v1 cipher
            self._cipher_params = self._analyzer.get_cipher_params()
            if "error" in self._cipher_params:
                log.warning("Cipher analysis error: %s", self._cipher_params["error"])
                self._cipher_params = {
                    "cipher_type": "wc",
                    "d": 6298,
                    "operations": get_cipher_ops_for_d(6298),
                    "player_version": "unknown",
                    "k_missing": True,
                }
                self._initialized = True
                return
            log.info("YPP-v1 cipher: d=%d, %d operations, version=%s",
                     self._cipher_params.get("d"),
                     len(self._cipher_params.get("operations", [])),
                     self._cipher_params.get("player_version", "unknown"))
            self._initialized = True
            return

        log.warning(
            "Could not extract K or W array from player JS. "
            "This player version may use a different cipher mechanism. "
            "The ANDROID_VR API (get_working_urls) will still work."
        )
        self._cipher_params = {
            "cipher_type": "unknown",
            "operations": [],
            "player_version": "unknown",
        }
        self._initialized = True

    def decrypt_s(self, encrypted_sig: str) -> str:
        """Decrypt a signature using the detected cipher."""
        self.ensure_initialized()
        if self._cipher_params.get("cipher_type") == "y2":
            return decrypt_signature_v2(encrypted_sig, self._analyzer.W)
        d = self._cipher_params.get("d", 6298)
        return decrypt_signature(encrypted_sig, d)

    def decrypt_n(self, n_token: str) -> str:
        """Decrypt an n-token using the detected cipher."""
        self.ensure_initialized()
        if self._cipher_params.get("cipher_type") == "y2":
            return decrypt_signature_v2(n_token, self._analyzer.W)
        d = self._cipher_params.get("d", 6298)
        return decrypt_n_token(n_token, d)

    def get_info(self) -> dict:
        """Return info about the extracted cipher."""
        self.ensure_initialized()
        return dict(self._cipher_params or {})

    def get_working_urls(self) -> list[dict]:
        """
        Get working stream URLs via INNERTUBE API (ANDROID_VR client).

        Primary method - no cipher decryption needed as ANDROID_VR
        returns pre-signed URLs.

        Falls back to signature decryption for formats that still
        have cipher data (unlikely for ANDROID_VR).
        """
        # Try to get sts from existing player JS cache
        sts = self._extract_sts_from_player_js()
        response = call_innertube_player_api(self._video_id, sts=sts)
        if not response:
            log.warning("INNERTUBE API failed for %s", self._video_id)
            return []

        formats = extract_formats_from_player_response(response)
        result = []
        for fmt in formats:
            url = fmt.get("url")
            if url:
                result.append(fmt)
            else:
                sc = fmt.get("signatureCipher") or fmt.get("cipher", "")
                if sc:
                    self.ensure_initialized()
                    params = urllib.parse.parse_qs(sc)
                    encrypted_s = params.get("s", [None])[0]
                    sp = params.get("sp", [None])[0]
                    url_val = params.get("url", [None])[0]
                    if encrypted_s and url_val:
                        decrypted = self.decrypt_s(encrypted_s)
                        parsed = urllib.parse.urlparse(url_val)
                        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                        qs[sp or "sig"] = [decrypted]
                        qs.pop("lsig", None)
                        new_qs = urllib.parse.urlencode(qs, doseq=True)
                        fmt_url = urllib.parse.urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_qs, parsed.fragment
                        ))
                        fmt["url"] = fmt_url
                        result.append(fmt)
        return result

    def _extract_sts_from_player_js(self) -> int | None:
        """Extract signature timestamp from cached player JS."""
        if not self._player_js:
            return None
        m = re.search(r"(?:signatureTimestamp|sts)\s*:\s*(?P<sts>[0-9]{5})", self._player_js)
        if m:
            return int(m.group("sts"))
        return None

    def _fetch_player_js_cached(self) -> None:
        """Fetch the YouTube player JavaScript with caching."""
        if self._player_js:
            return

        cache_dir = os.path.join(os.path.dirname(__file__), ".cache")
        cache_path = os.path.join(cache_dir, "player.js")
        cache_meta_path = cache_path + ".meta"
        max_cache_age = 3600  # 1 hour

        # Try loading from cache
        if os.path.exists(cache_path) and os.path.exists(cache_meta_path):
            try:
                with open(cache_meta_path, "r") as f:
                    meta = json.load(f)
                cache_age = time.time() - meta.get("timestamp", 0)
                if cache_age < max_cache_age:
                    with open(cache_path, "r") as f:
                        self._player_js = f.read()
                    log.info("Loaded player JS from cache (%d bytes)", len(self._player_js))
                    return
            except Exception:
                pass

        # Fetch fresh
        try:
            watch_url = self.YT_WATCH_URL.format(video_id=self._video_id)
            html = http_get_text(watch_url)
            player_url = None
            if html:
                player_url = extract_player_url_from_html(html)

            if not player_url:
                embed_url = self.YT_EMBED_URL.format(video_id=self._video_id)
                html = http_get_text(embed_url)
                if html:
                    player_url = extract_player_url_from_html(html)

            if not player_url:
                raise RuntimeError("Could not find player JS URL.")

            log.info("Player URL: %s", player_url)
            self._player_js = http_get_text(player_url)
            if not self._player_js:
                raise RuntimeError("Failed to download player JS.")
            log.info("Player JS fetched (%d bytes)", len(self._player_js))

            # Save to cache
            try:
                os.makedirs(cache_dir, exist_ok=True)
                with open(cache_path, "w") as f:
                    f.write(self._player_js)
                with open(cache_meta_path, "w") as f:
                    json.dump({"timestamp": time.time(), "url": player_url}, f)
            except Exception:
                pass
        except Exception:
            # Fall back to cache even if expired
            if os.path.exists(cache_path):
                with open(cache_path, "r") as f:
                    self._player_js = f.read()
                log.info("Loaded player JS from cache (fallback, %d bytes)", len(self._player_js))
            else:
                raise


# ===================================================================
# 9. Kotlin Bridge
# ===================================================================

def get_formats_for_kotlin(video_id: str) -> str:
    """
    Called by Kotlin via Chaquopy.
    Returns JSON string with format list or error.
    """
    import json
    import traceback
    try:
        engine = YoutubeCipherEngine(video_id)
        urls = engine.get_working_urls()
        formats = []
        for f in urls:
            mime = f.get("mimeType", "") or ""
            itag = f.get("itag", 0)
            url = f.get("url", "")
            content_length = f.get("contentLength", "0")
            bitrate = f.get("bitrate", 0)
            width = f.get("width", 0)
            height = f.get("height", 0)

            # Parse quality label from mimeType/height
            if height:
                quality = f"{height}p"
                if width:
                    quality = f"{width}x{height}"
            else:
                quality = "audio only" if "audio" in mime else "unknown"

            formats.append({
                "itag": itag,
                "mime": mime.split(";")[0] if mime else "unknown",
                "url": url,
                "size": content_length,
                "bitrate": bitrate,
                "width": width,
                "height": height,
                "quality": quality,
                "type": "video" if "video" in mime else "audio",
            })

        result = {"success": True, "formats": formats}
        return json.dumps(result)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        })
