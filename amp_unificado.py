#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AMP Unified Report Generator
- Generates 3 images per Cisco AMP group into the SAME group folder:
    - compromises.png  (from Amp_images.py -> "Compromises")
    - threats.png      (from Amp_images_hardcoded.py -> "Threats")
    - devices.png      (from Amp_todo.py -> "Devices")

Notes:
- Designs and data logic were preserved from the original scripts.
- AMP API auth/session is shared in a single AmpClient.
"""

import os
import re
import time
import json
import hashlib
import datetime as dt
from typing import Any, Dict, List, Tuple, Optional

import requests
from PIL import Image, ImageDraw, ImageFont

# ============================================================
# 1) CREDENCIALES (HARDCODE PRUEBAS)  <-- deja igual que tus scripts
# ============================================================
AMP_BASE_URL = "https://api.amp.cisco.com/v1"
AMP_CLIENT_ID = "1353f210ba2ab4201857"
AMP_API_KEY   = "b03af0dc-1a2f-43ed-83f1-344900b2e322"

# ============================================================
# 2) CONFIG GLOBAL
# ============================================================
PER_PAGE = 500
DAYS_BACK = 30

# Root único (todo unificado aquí)
OUTPUT_ROOT = os.path.join(os.getcwd(), "amp_reportes_unificado")
GROUP_THROTTLE_SECONDS = 0.30

# Devices script throttling
DEVICES_MAX_PAGES = 3000
DEVICES_SLEEP = 0.10
GENERATE_EMPTY_GROUPS = True

# Debug (conserva el comportamiento de los scripts originales)
DEBUG_COMPROMISES = False
SAVE_DEBUG_SAMPLES_COMPROMISES = False
SAMPLE_EVENTS_PER_GROUP_COMPROMISES = 30
MAX_PAGES_PER_GROUP_COMPROMISES = 250  # safety net

DEBUG_THREATS = False
SAVE_DEBUG_SAMPLES_THREATS = False
SAMPLE_EVENTS_PER_GROUP_THREATS = 25
MAX_PAGES_PER_GROUP_THREATS = 300


# ============================================================
# 3) HELPERS COMUNES
# ============================================================
def ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)

def sanitize_folder(name: str) -> str:
    name = (name or "").strip()
    # compatible Windows/Linux
    name = re.sub(r"[<>:\"/\\|?*\x00-\x1F]", "_", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name[:120] if len(name) > 120 else name

def iso_utc_compromises(d: dt.datetime) -> str:
    # preserva formato de Amp_images.py
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def iso_utc_threats(d: dt.datetime) -> str:
    # preserva formato de Amp_images_hardcoded.py
    return d.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def parse_wait_seconds_from_429_compromises(resp: requests.Response) -> int:
    ra = resp.headers.get("Retry-After")
    if ra:
        try:
            return max(1, int(ra))
        except Exception:
            pass
    try:
        j = resp.json()
        msg = ""
        if isinstance(j, dict) and "error" in j and isinstance(j["error"], dict):
            msg = j["error"].get("message", "") or ""
        m = re.search(r"next slot in\s+(\d+)\s*s", msg, re.IGNORECASE)
        if m:
            return max(1, int(m.group(1)))
    except Exception:
        pass
    return 30

def parse_wait_seconds_from_429_threats(resp: requests.Response) -> float:
    ra = resp.headers.get("Retry-After")
    if ra:
        try:
            return float(ra)
        except Exception:
            pass
    return 2.0

def parse_wait_seconds_from_429_devices(resp: requests.Response) -> float:
    ra = resp.headers.get("Retry-After")
    try:
        if ra and ra.replace(".", "", 1).isdigit():
            return float(ra)
    except Exception:
        pass
    return 2.0


# ============================================================
# 4) AMP CLIENT (ÚNICO)
# ============================================================
class AmpClient:
    def __init__(self, base_url: str, client_id: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.auth = (client_id, api_key)
        self.s = requests.Session()
        self.s.headers.update({"Accept": "application/json"})

    def _get_raw(self, path: str, params: Dict[str, Any], timeout: int = 60) -> requests.Response:
        url = f"{self.base_url}/{path.lstrip('/')}"
        return self.s.get(url, params=params, auth=self.auth, timeout=timeout)

    def get_groups(self) -> List[Dict[str, str]]:
        r = self._get_raw("groups", params={"limit": 500}, timeout=60)
        if r.status_code >= 300:
            raise RuntimeError(f"GET {r.url} failed: {r.status_code} {r.text[:400]}")
        data = r.json().get("data") or []
        out: List[Dict[str, str]] = []
        for g in data:
            name = str(g.get("name") or "Unknown")
            guid = str(g.get("guid") or g.get("group_guid") or "")
            if guid:
                out.append({"name": name, "guid": guid})
        return out

    # ----------- Events method (Compromises) -----------
    def get_events_in_range_for_group_compromises(
        self,
        group_guid: str,
        start_utc: dt.datetime,
        end_utc: dt.datetime,
        debug_dir: Optional[str] = None,
    ) -> List[dict]:
        all_events: List[dict] = []
        offset = 0
        pages = 0
        can_early_cut = True
        first_page_desc = None

        def ev_ts(ev: dict) -> Optional[int]:
            try:
                v = ev.get("timestamp")
                if isinstance(v, int):
                    return v
                if isinstance(v, float):
                    return int(v)
                if isinstance(v, str) and v.isdigit():
                    return int(v)
            except Exception:
                pass
            return None

        def event_fingerprint(ev: dict) -> str:
            if ev.get("id") is not None:
                return f"id:{ev.get('id')}"
            raw = json.dumps(ev, sort_keys=True, ensure_ascii=False).encode("utf-8")
            return "h:" + hashlib.sha1(raw).hexdigest()

        def dedupe_events(events: List[dict]) -> List[dict]:
            seen = set()
            out_ = []
            for ev in events:
                fp = event_fingerprint(ev)
                if fp in seen:
                    continue
                seen.add(fp)
                out_.append(ev)
            return out_

        def is_desc_sorted_ts(page: List[dict]) -> bool:
            ts = [ev_ts(e) for e in page]
            ts = [t for t in ts if t is not None]
            if len(ts) < 3:
                return True
            return all(ts[i] >= ts[i + 1] for i in range(len(ts) - 1))

        # fetch with rate-limit/backoff preserved from Amp_images.py
        max_retries = 10
        backoff_5xx = 2

        while True:
            pages += 1
            if pages > MAX_PAGES_PER_GROUP_COMPROMISES:
                if debug_dir:
                    ensure_dir(debug_dir)
                    with open(os.path.join(debug_dir, "WARN_max_pages.txt"), "w", encoding="utf-8") as f:
                        f.write(f"Se alcanzó MAX_PAGES_PER_GROUP={MAX_PAGES_PER_GROUP_COMPROMISES}.\n")
                break

            params = {
                "start_date": iso_utc_compromises(start_utc),
                "group_guid[]": group_guid,
                "limit": PER_PAGE,
                "offset": offset,
            }

            # retry loop (429 + 5xx)
            r = None
            for attempt in range(1, max_retries + 1):
                r = self._get_raw("events", params=params, timeout=60)

                if r.status_code == 429:
                    wait_s = parse_wait_seconds_from_429_compromises(r)
                    wait_s = min(180, wait_s + (attempt - 1) * 3)
                    print(f"⚠️ 429 Rate limit. Esperando {wait_s}s... ({attempt}/{max_retries})")
                    time.sleep(wait_s)
                    continue

                if r.status_code >= 500:
                    print(f"⚠️ HTTP {r.status_code}. Backoff {backoff_5xx}s... ({attempt}/{max_retries})")
                    time.sleep(backoff_5xx)
                    backoff_5xx = min(60, backoff_5xx * 2)
                    continue

                break

            if r is None:
                break

            if r.status_code >= 300:
                raise RuntimeError(f"GET {r.url} failed: {r.status_code} {r.text[:400]}")

            page = r.json().get("data") or []
            if not page:
                break

            if first_page_desc is None:
                first_page_desc = is_desc_sorted_ts(page)
                if not first_page_desc:
                    can_early_cut = False
                    if debug_dir:
                        ensure_dir(debug_dir)
                        with open(os.path.join(debug_dir, "WARN_order.txt"), "w", encoding="utf-8") as f:
                            f.write("Primera página NO está ordenada desc por timestamp. Corte temprano desactivado.\n")

            all_events.extend(page)

            if can_early_cut:
                last_ts = ev_ts(page[-1])
                if last_ts is not None:
                    last_dt = dt.datetime.fromtimestamp(last_ts, tz=dt.timezone.utc)
                    if last_dt < start_utc:
                        break

            if len(page) < PER_PAGE:
                break

            offset += len(page)

        all_events = dedupe_events(all_events)

        # Filtrado local exacto al rango
        filtered = []
        ts_missing = 0
        for ev in all_events:
            ts = ev_ts(ev)
            if ts is None:
                ts_missing += 1
                continue
            t = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)
            if start_utc <= t < end_utc:
                filtered.append(ev)

        # Debug igual que script original
        if debug_dir:
            ensure_dir(debug_dir)

            def extract_event_type(ev: dict) -> str:
                return str(ev.get("event_type") or "unknown")

            def top_counts(items: List[str], topn: int = 10) -> List[Tuple[str, int]]:
                c: Dict[str, int] = {}
                for it in items:
                    c[it] = c.get(it, 0) + 1
                return sorted(c.items(), key=lambda x: x[1], reverse=True)[:topn]

            raw_types = [extract_event_type(e) for e in filtered]
            raw_top = top_counts(raw_types, 20)
            suggested_allowlist = [name for name, _ in raw_top]

            stats = {
                "start_utc": iso_utc_compromises(start_utc),
                "end_utc": iso_utc_compromises(end_utc),
                "pages_fetched": pages,
                "events_in_range_total": len(filtered),
                "timestamp_missing": ts_missing,
                "top_event_types_in_range": raw_top,
                "suggested_allowlist_candidates": suggested_allowlist,
            }

            with open(os.path.join(debug_dir, "debug_stats.json"), "w", encoding="utf-8") as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)

            if SAVE_DEBUG_SAMPLES_COMPROMISES:
                with open(os.path.join(debug_dir, "events_sample_in_range.json"), "w", encoding="utf-8") as f:
                    json.dump(filtered[:SAMPLE_EVENTS_PER_GROUP_COMPROMISES], f, ensure_ascii=False, indent=2)

        return filtered

    # ----------- Events method (Threats) -----------
    def get_events_last30_for_group_threats(self, group_guid: str, start_utc: dt.datetime, end_utc: dt.datetime) -> List[dict]:
        start_ts = int(start_utc.timestamp())
        end_ts = int(end_utc.timestamp())

        offset = 0
        pages = 0
        out: List[dict] = []

        while True:
            pages += 1
            if pages > MAX_PAGES_PER_GROUP_THREATS:
                break

            params = {
                "start_date": iso_utc_threats(start_utc),
                "group_guid[]": group_guid,
                "limit": PER_PAGE,
                "offset": offset,
            }

            while True:
                r = self._get_raw("events", params=params, timeout=30)
                if r.status_code == 429:
                    time.sleep(parse_wait_seconds_from_429_threats(r))
                    continue
                break

            if r.status_code >= 300:
                raise RuntimeError(f"GET {r.url} failed: {r.status_code} {r.text[:400]}")

            page = r.json().get("data") or []
            if not page:
                break

            for ev in page:
                ts = ev.get("timestamp")
                if isinstance(ts, (int, float)):
                    ts_i = int(ts)
                elif isinstance(ts, str) and ts.isdigit():
                    ts_i = int(ts)
                else:
                    continue

                if start_ts <= ts_i < end_ts:
                    out.append(ev)

            if len(page) < PER_PAGE:
                break
            offset += len(page)

        # Dedup (igual que original)
        seen = set()
        deduped = []
        for ev in out:
            fp = hashlib.sha256(json.dumps(
                {"t": ev.get("timestamp"), "tid": ev.get("event_type_id"), "det": ev.get("detection_id")},
                sort_keys=True, ensure_ascii=False
            ).encode("utf-8", errors="ignore")).hexdigest()
            if fp in seen:
                continue
            seen.add(fp)
            deduped.append(ev)

        return deduped

    # ----------- Devices method (Computers) -----------
    def get_devices_computers_page(self, limit: int, offset: int) -> Dict[str, Any]:
        params = {"limit": limit, "offset": offset}
        while True:
            r = self._get_raw("computers", params=params, timeout=60)
            if r.status_code == 429:
                time.sleep(parse_wait_seconds_from_429_devices(r))
                continue
            if r.status_code >= 300:
                raise RuntimeError(f"GET {r.url} failed: {r.status_code} {r.text[:400]}")
            return r.json()


# ============================================================
# 5) COMPROMISES (del Amp_images.py) - DISEÑO + LOGICA IGUAL
# ============================================================
COMPROMISE_EVENT_TYPES = {
    "DFC Threat Detected",
    "Threat Detected",
    "Threat Quarantined",
    "Quarantine Failure",
    "Quarantine Failed",
    "Threat Not Quarantined",
    "Pcalua Launched Suspicious Process",
    "Scan Completed With Detection",
    "AnyDesk Suspicious File Creation",
}

C_CARD_W, C_CARD_H = 1100, 900
C_MARGIN = 40

C_COL_BG = (255, 255, 255)
C_COL_BORDER = (230, 230, 230)
C_COL_TITLE = (0, 120, 185)
C_COL_TEXT = (60, 60, 60)
C_COL_MUTED = (120, 120, 120)

C_COL_RED = (210, 35, 42)
C_COL_ORANGE = (243, 134, 33)
C_COL_YELLOW = (244, 195, 0)
C_COL_BAR_BG = (245, 245, 245)

def c_load_font(size: int):
    candidates = [
        "arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ]
    for p in candidates:
        try:
            return ImageFont.truetype(p, size)
        except Exception:
            continue
    return ImageFont.load_default()

C_FONT_TITLE = c_load_font(46)
C_FONT_H2 = c_load_font(28)
C_FONT_BODY = c_load_font(22)

def c_shorten(s: str, n: int = 30) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 3] + "..."

def c_extract_event_type(ev: dict) -> str:
    return str(ev.get("event_type") or "unknown")

def c_extract_host(ev: dict) -> str:
    c = ev.get("computer") or {}
    return str(c.get("hostname") or "unknown-host")

def c_top_counts(items: List[str], topn: int = 10) -> List[Tuple[str, int]]:
    c: Dict[str, int] = {}
    for it in items:
        c[it] = c.get(it, 0) + 1
    return sorted(c.items(), key=lambda x: x[1], reverse=True)[:topn]

def filter_compromise_events(events_in_range: List[dict]) -> List[dict]:
    out = []
    for ev in events_in_range:
        if c_extract_event_type(ev) in COMPROMISE_EVENT_TYPES:
            out.append(ev)
    return out

def c_draw_card_base(title: str):
    img = Image.new("RGB", (C_CARD_W, C_CARD_H), C_COL_BG)
    d = ImageDraw.Draw(img)
    d.rectangle([8, 8, C_CARD_W - 8, C_CARD_H - 8], outline=C_COL_BORDER, width=3)
    d.text((C_MARGIN, C_MARGIN - 5), title, fill=C_COL_TITLE, font=C_FONT_TITLE)
    return img, d

def c_draw_hbar(d: ImageDraw.ImageDraw, x: int, y: int, w: int, h: int,
                value: int, max_value: int, color, bg=C_COL_BAR_BG):
    d.rounded_rectangle([x, y, x + w, y + h], radius=8, fill=bg)
    if max_value <= 0:
        return
    fw = int((value / max_value) * w)
    if fw < 1 and value > 0:
        fw = 1
    d.rounded_rectangle([x, y, x + fw, y + h], radius=8, fill=color)

def c_section_title(d: ImageDraw.ImageDraw, x: int, y: int, text: str):
    d.text((x, y), text, fill=C_COL_MUTED, font=C_FONT_H2)

def c_label_linklike(d: ImageDraw.ImageDraw, x: int, y: int, text: str):
    d.text((x, y), text, fill=C_COL_TITLE, font=C_FONT_BODY)

def render_compromises_card(compromise_events: List[dict], outpath: str):
    img, d = c_draw_card_base("Compromises")

    event_types = [c_extract_event_type(e) for e in compromise_events]
    hosts = [c_extract_host(e) for e in compromise_events]

    total = len(event_types)
    in_prog = 0
    resolved = 0

    y0 = 120
    d.text((C_MARGIN, y0),
           f"{total} Compromises total - {in_prog} In Progress - {resolved} Resolved",
           fill=C_COL_TEXT, font=C_FONT_BODY)

    c_draw_hbar(d, C_MARGIN, y0 + 45, C_CARD_W - 2 * C_MARGIN, 26, total, max(1, total), C_COL_RED)

    c_section_title(d, C_MARGIN, y0 + 95, "By Event")
    top_ev = c_top_counts(event_types, 5)
    maxv = top_ev[0][1] if top_ev else 1

    y = y0 + 140
    for name, val in top_ev:
        c_label_linklike(d, C_MARGIN, y, c_shorten(name, 26))
        color = C_COL_ORANGE if val == maxv else C_COL_YELLOW
        c_draw_hbar(d, 420, y + 6, 520, 20, val, maxv, color)
        d.text((950, y), str(val), fill=C_COL_TEXT, font=C_FONT_BODY)
        y += 44

    c_section_title(d, C_MARGIN, y + 10, "By Host")
    top_h = c_top_counts(hosts, 5)
    maxh = top_h[0][1] if top_h else 1

    y2 = y + 55
    for name, val in top_h:
        c_label_linklike(d, C_MARGIN, y2, c_shorten(name, 28))
        color = C_COL_ORANGE if val == maxh else C_COL_YELLOW
        c_draw_hbar(d, 420, y2 + 6, 520, 20, val, maxh, color)
        d.text((950, y2), str(val), fill=C_COL_TEXT, font=C_FONT_BODY)
        y2 += 44

    img.save(outpath, "PNG")


# ============================================================
# 6) THREATS (del Amp_images_hardcoded.py) - DISEÑO + LOGICA IGUAL
# ============================================================
EVENT_ID_THREAT_DETECTED = 1090519054
EVENT_ID_THREAT_QUARANTINED = 553648143
EVENT_ID_QUARANTINE_FAILURE = 2164260880
EVENT_ID_CLOUD_RECALL_DETECTION = 553648147
EVENT_ID_CLOUD_RECALL_QUARANTINE_SUCCESS = 553648155

THREATS_RELEVANT_EVENT_TYPE_IDS = {
    EVENT_ID_THREAT_DETECTED,
    EVENT_ID_THREAT_QUARANTINED,
    EVENT_ID_QUARANTINE_FAILURE,
    EVENT_ID_CLOUD_RECALL_DETECTION,
    EVENT_ID_CLOUD_RECALL_QUARANTINE_SUCCESS,
}

T_CARD_W, T_CARD_H = 1100, 940
T_MARGIN = 40

T_COL_BG = (255, 255, 255)
T_COL_BORDER = (230, 230, 230)

T_COL_TEXT = (31, 31, 31)
T_COL_LINK = (26, 115, 232)

T_COL_PURPLE = (142, 68, 173)
T_COL_YELLOW = (244, 180, 0)
T_COL_RED = (211, 47, 47)
T_COL_GRAY = (120, 120, 120)

def t_load_font(size: int, bold: bool = False):
    candidates = []
    if os.name == "nt":
        candidates = [r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\arial.ttf"]
        if bold:
            candidates = [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"] + candidates
    else:
        candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ]
    for p in candidates:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size=size)
            except Exception:
                pass
    return ImageFont.load_default()

T_FONT_TITLE = t_load_font(44, bold=True)
T_FONT_H2    = t_load_font(28, bold=True)
T_FONT_BODY  = t_load_font(22, bold=False)

def t_shorten(s: str, n: int) -> str:
    s = str(s or "")
    return s if len(s) <= n else (s[: n - 3] + "...")

def t_extract_event_type_id(ev: dict) -> Optional[int]:
    v = ev.get("event_type_id")
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return None

def t_extract_host(ev: dict) -> str:
    c = ev.get("computer") or {}
    return str(c.get("hostname") or "unknown-host")

def t_extract_detection_id(ev: dict) -> Optional[str]:
    v = ev.get("detection_id")
    if isinstance(v, str) and v.strip():
        return v.strip()
    d = ev.get("detection") or {}
    if isinstance(d, dict):
        vv = d.get("id") or d.get("detection_id")
        if isinstance(vv, str) and vv.strip():
            return vv.strip()
    return None

def t_extract_sha256(ev: dict) -> Optional[str]:
    f = ev.get("file") or {}
    if isinstance(f, dict):
        sha = f.get("sha256")
        if isinstance(sha, str) and sha.strip():
            return sha.strip()
    sha2 = ev.get("sha256")
    if isinstance(sha2, str) and sha2.strip():
        return sha2.strip()
    return None

def t_extract_file_name(ev: dict) -> Optional[str]:
    f = ev.get("file") or {}
    if isinstance(f, dict):
        for k in ("file_name", "name", "path"):
            v = f.get(k)
            if isinstance(v, str) and v.strip():
                return os.path.basename(v.strip())
    for k in ("file_name", "filename", "fileName", "path"):
        v = ev.get(k)
        if isinstance(v, str) and v.strip():
            return os.path.basename(v.strip())
    return None

def t_top_counts(items: List[str], topn: int = 10) -> List[Tuple[str, int]]:
    c: Dict[str, int] = {}
    for it in items:
        it = str(it or "")
        c[it] = c.get(it, 0) + 1
    return sorted(c.items(), key=lambda x: x[1], reverse=True)[:topn]

_THREAT_KEYS = {
    "threat_name", "threatname",
    "malware_name", "malwarename",
    "signature", "signature_name", "signaturename",
    "detection_name", "detectionname",
    "virus_name", "virusname",
    "threat", "threattitle", "title", "name",
    "threat_label", "threatlabel",
    "classification", "family", "family_name", "familyname",
}

_MALWARE_LIKE_RE = re.compile(r"(?:\bW32\.|Talos\b|Trojan\b|Backdoor\b|Ransom\b|Exploit\b|Win32\b|Gen\b|PUA\b|Adware\b)", re.IGNORECASE)

def _t_is_good_threat_string(s: str) -> bool:
    if not s or not isinstance(s, str):
        return False
    s = s.strip()
    if not s:
        return False
    if s.lower() in ("unknown", "unknown-threat", "unknown file", "unknown-file", "n/a", "na"):
        return False
    if re.fullmatch(r"[a-f0-9]{32,64}", s.lower()):
        return False
    return True

def _t_walk_strings(obj: Any, max_depth: int = 8):
    def _walk(x: Any, depth: int):
        if depth > max_depth:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                kl = str(k).lower() if isinstance(k, str) else ""
                if isinstance(v, str):
                    yield (kl, v)
                elif isinstance(v, (dict, list)):
                    yield from _walk(v, depth + 1)
        elif isinstance(x, list):
            for it in x:
                if isinstance(it, str):
                    yield ("", it)
                elif isinstance(it, (dict, list)):
                    yield from _walk(it, depth + 1)
    yield from _walk(obj, 0)

def t_extract_threat_name(ev: dict) -> Optional[str]:
    dets = ev.get("detections")
    if isinstance(dets, list):
        for d in dets:
            if isinstance(d, dict):
                for k in ("threat_name", "threatName", "signature", "signature_name", "malware_name", "detection_name", "name", "title", "family", "classification"):
                    v = d.get(k)
                    if isinstance(v, str) and _t_is_good_threat_string(v):
                        return v.strip()

    det = ev.get("detection")
    if isinstance(det, dict):
        for k in ("threat_name", "signature", "malware_name", "detection_name", "name", "title", "family", "classification"):
            v = det.get(k)
            if isinstance(v, str) and _t_is_good_threat_string(v):
                return v.strip()

    candidates_strong: List[str] = []
    candidates_weak: List[str] = []

    for kl, v in _t_walk_strings(ev, max_depth=9):
        if not isinstance(v, str):
            continue
        vs = v.strip()
        if not _t_is_good_threat_string(vs):
            continue

        if kl in _THREAT_KEYS or any(k in kl for k in ("threat", "malware", "signature", "detection", "virus", "family", "classification")):
            if _MALWARE_LIKE_RE.search(vs):
                candidates_strong.append(vs)
            else:
                candidates_weak.append(vs)

    if candidates_strong:
        candidates_strong.sort(key=lambda s: (len(s), s))
        return candidates_strong[0]
    if candidates_weak:
        candidates_weak.sort(key=lambda s: (len(s), s))
        return candidates_weak[0]

    return None

def t_classify_resolution_from_event_type_ids(type_ids: List[int]) -> Optional[str]:
    if EVENT_ID_QUARANTINE_FAILURE in type_ids:
        return "Quarantine Failed"
    if EVENT_ID_THREAT_QUARANTINED in type_ids or EVENT_ID_CLOUD_RECALL_QUARANTINE_SUCCESS in type_ids:
        return "Quarantined"
    return None

def build_unique_threats_by_detection_id(events: List[dict]) -> List[dict]:
    filtered = []
    for ev in events:
        tid = t_extract_event_type_id(ev)
        if tid is not None and tid not in THREATS_RELEVANT_EVENT_TYPE_IDS:
            continue
        filtered.append(ev)

    by_det: Dict[str, List[dict]] = {}
    for ev in filtered:
        det_id = t_extract_detection_id(ev)
        if not det_id:
            continue
        by_det.setdefault(det_id, []).append(ev)

    threats: List[dict] = []

    for det_id, evs in by_det.items():
        type_ids = [t for t in (t_extract_event_type_id(e) for e in evs) if isinstance(t, int)]
        has_detected = (EVENT_ID_THREAT_DETECTED in type_ids) or (EVENT_ID_CLOUD_RECALL_DETECTION in type_ids)
        if type_ids and not has_detected:
            continue

        def prio(e: dict) -> int:
            tid = t_extract_event_type_id(e)
            if tid in (EVENT_ID_THREAT_DETECTED, EVENT_ID_CLOUD_RECALL_DETECTION):
                return 0
            return 1

        best_file = None
        best_threat = None

        for ev in sorted(evs, key=prio):
            if not best_file:
                best_file = t_extract_file_name(ev)
            if not best_threat:
                best_threat = t_extract_threat_name(ev)
            if best_file and best_threat:
                break

        if not best_file or not best_threat:
            for ev in evs:
                if not best_file:
                    best_file = t_extract_file_name(ev)
                if not best_threat:
                    best_threat = t_extract_threat_name(ev)
                if best_file and best_threat:
                    break

        if not best_file:
            best_file = "unknown-file"
        if not best_threat:
            sha = t_extract_sha256(evs[0])
            best_threat = f"SHA256:{sha[:12]}…" if sha else "unknown-threat"

        resolution = t_classify_resolution_from_event_type_ids(type_ids) if type_ids else None
        host = t_extract_host(evs[0])

        threats.append({
            "detection_id": det_id,
            "host": host,
            "file_name": best_file,
            "threat_name": best_threat,
            "resolution": resolution,
            "event_type_ids": type_ids,
        })

    return threats

def t_draw_card_base(title: str) -> Tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", (T_CARD_W, T_CARD_H), T_COL_BG)
    d = ImageDraw.Draw(img)
    d.rectangle([10, 10, T_CARD_W - 10, T_CARD_H - 10], outline=T_COL_BORDER, width=3)
    d.text((T_MARGIN, 40), title, fill=T_COL_LINK, font=T_FONT_TITLE)
    return img, d

def t_section_title(d: ImageDraw.ImageDraw, x: int, y: int, text: str):
    d.text((x, y), text, fill=T_COL_TEXT, font=T_FONT_H2)

def t_label_linklike(d: ImageDraw.ImageDraw, x: int, y: int, text: str):
    d.text((x, y), text, fill=T_COL_LINK, font=T_FONT_BODY)

def t_draw_donut(d: ImageDraw.ImageDraw, cx: int, cy: int, outer_r: int, inner_r: int, color):
    d.ellipse([cx - outer_r, cy - outer_r, cx + outer_r, cy + outer_r], fill=color)
    d.ellipse([cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r], fill=T_COL_BG)

def t_draw_hbar(d: ImageDraw.ImageDraw, x: int, y: int, w: int, h: int, val: int, maxv: int, color):
    maxv = max(1, int(maxv))
    val = max(0, int(val))
    ww = int(w * (val / maxv))
    d.rectangle([x, y, x + ww, y + h], fill=color)

def render_threats_card(unique_threats: List[dict], outpath: str):
    img, d = t_draw_card_base("Threats")

    files = [t["file_name"] for t in unique_threats]
    hosts = [t["host"] for t in unique_threats]
    threat_names = [t["threat_name"] for t in unique_threats]
    resolutions = [t["resolution"] for t in unique_threats if t.get("resolution")]

    top_file = t_top_counts(files, 1)
    top_file_name, _ = (top_file[0] if top_file else ("No data", 0))

    res_counter = {"Quarantined": 0, "Quarantine Failed": 0}
    for r in resolutions:
        if r in res_counter:
            res_counter[r] += 1

    top_host = t_top_counts(hosts, 1)
    top_host_name, top_host_count = (top_host[0] if top_host else ("No data", 0))

    top_th = t_top_counts(threat_names, 2)

    y0 = 125

    t_section_title(d, T_MARGIN, y0, "Root Cause")
    donut_cx = T_MARGIN + 140
    donut_cy = y0 + 185
    t_draw_donut(d, donut_cx, donut_cy, 90, 55, T_COL_PURPLE)
    d.rectangle([T_MARGIN + 310, y0 + 150, T_MARGIN + 332, y0 + 172], fill=T_COL_PURPLE)
    t_label_linklike(d, T_MARGIN + 345, y0 + 145, t_shorten(top_file_name, 40))

    t_section_title(d, T_MARGIN, y0 + 360, "Resolution")
    bar_x, bar_w, bar_h = 420, 520, 22
    row_y = y0 + 410
    max_res = max(1, res_counter["Quarantined"], res_counter["Quarantine Failed"])

    t_label_linklike(d, T_MARGIN, row_y - 4, "Quarantined")
    t_draw_hbar(d, bar_x, row_y, bar_w, bar_h, res_counter["Quarantined"], max_res, T_COL_YELLOW)
    d.text((950, row_y - 6), str(res_counter["Quarantined"]), fill=T_COL_TEXT, font=T_FONT_BODY)

    row_y2 = row_y + 44
    t_label_linklike(d, T_MARGIN, row_y2 - 4, "Quarantine Failed")
    t_draw_hbar(d, bar_x, row_y2, bar_w, bar_h, res_counter["Quarantine Failed"], max_res, T_COL_RED)
    d.text((950, row_y2 - 6), str(res_counter["Quarantine Failed"]), fill=T_COL_TEXT, font=T_FONT_BODY)

    t_section_title(d, T_MARGIN, y0 + 500, "By Host")
    y_host = y0 + 555
    t_label_linklike(d, T_MARGIN, y_host - 4, t_shorten(top_host_name, 32))
    t_draw_hbar(d, bar_x, y_host, bar_w, bar_h, top_host_count, max(1, top_host_count), T_COL_YELLOW)
    d.text((950, y_host - 6), str(top_host_count), fill=T_COL_TEXT, font=T_FONT_BODY)

    t_section_title(d, T_MARGIN, y0 + 640, "By Threat Name")
    y_th = y0 + 695
    max_th = top_th[0][1] if top_th else 1

    if top_th:
        for i, (nm, val) in enumerate(top_th):
            yy = y_th + i * 44
            t_label_linklike(d, T_MARGIN, yy - 4, t_shorten(nm, 40))
            t_draw_hbar(d, bar_x, yy, bar_w, bar_h, val, max_th, T_COL_YELLOW)
            d.text((950, yy - 6), str(val), fill=T_COL_TEXT, font=T_FONT_BODY)
    else:
        d.text((T_MARGIN, y_th - 10), "No threat-name data", fill=T_COL_GRAY, font=T_FONT_BODY)

    if not unique_threats:
        d.text((T_MARGIN, y0 + 90), "No data in last 30 days", fill=T_COL_GRAY, font=T_FONT_BODY)

    img.save(outpath, "PNG")


# ============================================================
# 7) DEVICES (del Amp_todo.py) - DISEÑO + LOGICA IGUAL
# ============================================================
D_CARD_W, D_CARD_H = 900, 600
D_MARGIN = 30

D_COL_BG = (255, 255, 255)
D_COL_BORDER = (230, 230, 230)
D_COL_TEXT = (31, 31, 31)
D_COL_LINK = (26, 115, 232)

D_COL_PURPLE = (142, 68, 173)
D_COL_BLUE = (66, 133, 244)
D_COL_YELLOW = (244, 180, 0)
D_COL_GRAY = (120, 120, 120)

def d_load_font(size: int, bold: bool = False):
    candidates = []
    if os.name == "nt":
        candidates = [r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\arial.ttf"]
        if bold:
            candidates = [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"] + candidates
    else:
        if bold:
            candidates = ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"]
        candidates += ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]
    for p in candidates:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size=size)
            except Exception:
                pass
    return ImageFont.load_default()

D_FONT_TITLE = d_load_font(44, bold=True)
D_FONT_H2    = d_load_font(26, bold=True)
D_FONT_BODY  = d_load_font(20, bold=False)

def d_norm(x: Any) -> str:
    return (str(x) if x is not None else "").strip()

def d_parse_os_bucket(operating_system: Any) -> str:
    s = d_norm(operating_system)
    if not s:
        return "Unknown OS"

    m = re.match(r"^(Windows\s+\d+)\b", s, flags=re.IGNORECASE)
    if m:
        x = m.group(1)
        return x[0].upper() + x[1:]

    m2 = re.match(r"^(Windows\s+Server\s+\d{4})\b", s, flags=re.IGNORECASE)
    if m2:
        x = m2.group(1)
        return x[0].upper() + x[1:]

    if "mac" in s.lower() or "os x" in s.lower():
        return "macOS"
    if any(k in s.lower() for k in ("linux", "ubuntu", "debian", "red hat", "centos", "rhel")):
        return "Linux"
    if "android" in s.lower():
        return "Android"
    if any(k in s.lower() for k in ("ios", "iphone", "ipad")):
        return "iOS"

    return s.split(",")[0].strip() or "Unknown OS"

def d_count_top(items: List[str]) -> List[Tuple[str, int]]:
    d_: Dict[str, int] = {}
    for x in items:
        x = d_norm(x) or "Unknown"
        d_[x] = d_.get(x, 0) + 1
    return sorted(d_.items(), key=lambda kv: kv[1], reverse=True)

def iter_all_computers(amp: AmpClient) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    offset = 0
    pages = 0
    while True:
        pages += 1
        if pages > DEVICES_MAX_PAGES:
            break
        js = amp.get_devices_computers_page(limit=PER_PAGE, offset=offset)
        data = js.get("data") or []
        if not data:
            break
        out.extend(data)
        if len(data) < PER_PAGE:
            break
        offset += len(data)
        time.sleep(DEVICES_SLEEP)
    return out

def build_group_membership_index(computers: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    idx: Dict[str, List[Dict[str, Any]]] = {}

    def add(guid: str, c: Dict[str, Any]):
        if not guid:
            return
        idx.setdefault(guid, []).append(c)

    for c in computers:
        add(d_norm(c.get("group_guid")), c)

        gs = c.get("groups")
        if isinstance(gs, list):
            for g in gs:
                if isinstance(g, dict):
                    add(d_norm(g.get("guid")), c)

        link = ((c.get("links") or {}).get("group") or "")
        if isinstance(link, str) and "/groups/" in link:
            parts = link.rstrip("/").split("/groups/")
            if len(parts) == 2:
                add(d_norm(parts[1]), c)

    for gid, lst in list(idx.items()):
        seen = set()
        ded = []
        for c in lst:
            cg = d_norm(c.get("connector_guid"))
            key = cg if cg else json.dumps(c, sort_keys=True, ensure_ascii=False)
            if key in seen:
                continue
            seen.add(key)
            ded.append(c)
        idx[gid] = ded

    return idx

def compute_supported_unsupported_baseline(windows_eps: List[Dict[str, Any]]) -> Tuple[int, int, str]:
    versions = [d_norm(c.get("connector_version")) for c in windows_eps if d_norm(c.get("connector_version"))]
    if not versions:
        return (0, 0, "no_connector_version")
    counts = d_count_top(versions)
    baseline = counts[0][0]
    sup = 0
    uns = 0
    for c in windows_eps:
        v = d_norm(c.get("connector_version"))
        if not v:
            continue
        if v == baseline:
            sup += 1
        else:
            uns += 1
    return (sup, uns, baseline)

def d_draw_card_base(title: str) -> Tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", (D_CARD_W, D_CARD_H), D_COL_BG)
    d = ImageDraw.Draw(img)
    d.rectangle([8, 8, D_CARD_W - 8, D_CARD_H - 8], outline=D_COL_BORDER, width=3)
    d.text((D_MARGIN, 28), title, fill=D_COL_LINK, font=D_FONT_TITLE)
    return img, d

def d_section_title(d: ImageDraw.ImageDraw, x: int, y: int, text: str):
    d.text((x, y), text, fill=D_COL_TEXT, font=D_FONT_H2)

def d_label_linklike(d: ImageDraw.ImageDraw, x: int, y: int, text: str):
    d.text((x, y), text, fill=D_COL_LINK, font=D_FONT_BODY)

def d_label_normal(d: ImageDraw.ImageDraw, x: int, y: int, text: str, color=D_COL_TEXT):
    d.text((x, y), text, fill=color, font=D_FONT_BODY)

def d_draw_donut(d: ImageDraw.ImageDraw, cx: int, cy: int, outer_r: int, inner_r: int, color):
    d.ellipse([cx - outer_r, cy - outer_r, cx + outer_r, cy + outer_r], fill=color)
    d.ellipse([cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r], fill=D_COL_BG)

def d_draw_version_bar(d: ImageDraw.ImageDraw, x: int, y: int, w: int, h: int, supported: int, unsupported: int):
    total = max(1, supported + unsupported)
    w_sup = int(w * (supported / total))
    w_uns = w - w_sup
    if w_sup > 0:
        d.rectangle([x, y, x + w_sup, y + h], fill=D_COL_BLUE)
    if w_uns > 0:
        d.rectangle([x + w_sup, y, x + w_sup + w_uns, y + h], fill=D_COL_YELLOW)

def render_devices_card(top_os: str, supported: int, unsupported: int, outpath: str, empty_note: bool):
    img, d = d_draw_card_base("Devices")

    y0 = 118

    d_section_title(d, D_MARGIN, y0, "By Host")
    donut_cx = D_MARGIN + 140
    donut_cy = y0 + 150
    d_draw_donut(d, donut_cx, donut_cy, 90, 55, D_COL_PURPLE)

    d.rectangle([D_MARGIN + 310, y0 + 125, D_MARGIN + 332, y0 + 147], fill=D_COL_PURPLE)
    d_label_linklike(d, D_MARGIN + 345, y0 + 120, top_os)

    VD_Y = y0 + 295
    d_section_title(d, D_MARGIN, VD_Y, "Version Deployment")

    d_label_normal(d, D_MARGIN, VD_Y + 50, "Update Status", D_COL_TEXT)

    d_label_linklike(d, D_MARGIN + 220, VD_Y + 50, f"{supported} Supported")
    d.text((D_MARGIN + 560, VD_Y + 50), f"{unsupported} Unsupported", fill=D_COL_YELLOW, font=D_FONT_BODY)

    d_label_linklike(d, D_MARGIN, VD_Y + 95, "Windows")

    bar_x = D_MARGIN + 220
    bar_y = VD_Y + 102
    bar_w = 560
    bar_h = 18

    d.rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + bar_h], fill=(230, 230, 230))
    d_draw_version_bar(d, bar_x, bar_y, bar_w, bar_h, supported, unsupported)

    d_label_normal(d, bar_x + bar_w + 12, VD_Y + 93, f"{supported} / {unsupported}", D_COL_TEXT)

    if empty_note:
        d.text((D_MARGIN, D_CARD_H - 60), "No endpoints in this group", fill=D_COL_GRAY, font=D_FONT_BODY)

    img.save(outpath, "PNG")


# ============================================================
# 8) MAIN (UNIFICADO)
# ============================================================
def main():
    if "PEGA_AQUI" in AMP_CLIENT_ID or "PEGA_AQUI" in AMP_API_KEY:
        raise SystemExit("Configura AMP_CLIENT_ID y AMP_API_KEY dentro del script (hardcoded para pruebas).")

    amp = AmpClient(AMP_BASE_URL, AMP_CLIENT_ID, AMP_API_KEY)

    now = dt.datetime.now(dt.timezone.utc)
    start_utc = now - dt.timedelta(days=DAYS_BACK)
    end_utc = now

    ts = now.strftime("%Y%m%d_%H%M%SZ")
    out_root = os.path.join(OUTPUT_ROOT, f"unificado_{ts}")
    ensure_dir(out_root)

    groups = amp.get_groups()
    print(f"✅ Groups detectados: {len(groups)}")
    print(f"✅ Rango UTC (events): start={iso_utc_compromises(start_utc)} | end={iso_utc_compromises(end_utc)}")

    # Devices: prefetch computers una sola vez (igual que Amp_todo.py, pero compartiendo auth)
    computers = iter_all_computers(amp)
    print(f"✅ Computers tenant: {len(computers)}")
    membership_idx = build_group_membership_index(computers)
    print(f"✅ Group membership index built: {len(membership_idx)} group IDs con endpoints")

    for g in groups:
        gname = g["name"]
        gguid = g["guid"]

        safe_name = sanitize_folder(gname)
        out_dir = os.path.join(out_root, safe_name)
        ensure_dir(out_dir)

        # 1) COMPROMISES -> compromises.png
        try:
            events_in_range = amp.get_events_in_range_for_group_compromises(
                group_guid=gguid,
                start_utc=start_utc,
                end_utc=end_utc,
                debug_dir=None,
            )
            compromise_events = filter_compromise_events(events_in_range)

            out_img_comp = os.path.join(out_dir, "compromises.png")
            render_compromises_card(compromise_events, out_img_comp)

            print(f"✅ {gname}: compromises={len(compromise_events)} -> {out_img_comp}")
        except Exception as e:
            print(f"⚠️ {gname}: error compromises ({e})")

        # 2) THREATS -> threats.png
        try:
            events_thr = amp.get_events_last30_for_group_threats(gguid, start_utc, end_utc)
            threats = build_unique_threats_by_detection_id(events_thr)

            out_img_thr = os.path.join(out_dir, "threats.png")
            render_threats_card(threats, out_img_thr)

            print(f"✅ {gname}: threats={len(threats)} -> {out_img_thr}")
        except Exception as e:
            print(f"⚠️ {gname}: error threats ({e})")

        # 3) DEVICES -> devices.png
        try:
            endpoints = membership_idx.get(gguid, [])
            if not endpoints and not GENERATE_EMPTY_GROUPS:
                print(f"⏭️ {gname}: sin endpoints (skip devices)")
            else:
                os_buckets = [d_parse_os_bucket(c.get("operating_system")) for c in endpoints]
                os_counts = d_count_top(os_buckets)
                top_os = os_counts[0][0] if os_counts else "Unknown OS"

                windows_eps = [c for c in endpoints if d_parse_os_bucket(c.get("operating_system")).lower().startswith("windows")]
                sup, uns, baseline = compute_supported_unsupported_baseline(windows_eps)

                out_img_dev = os.path.join(out_dir, "devices.png")
                render_devices_card(
                    top_os=top_os,
                    supported=sup,
                    unsupported=uns,
                    outpath=out_img_dev,
                    empty_note=(len(endpoints) == 0),
                )

                print(f"✅ {gname}: devices endpoints={len(endpoints)} windows={len(windows_eps)} sup={sup} uns={uns} -> {out_img_dev}")
        except Exception as e:
            print(f"⚠️ {gname}: error devices ({e})")

        time.sleep(GROUP_THROTTLE_SECONDS)

    print(f"✅ Listo. Carpeta final: {out_root}")

if __name__ == "__main__":
    main()
