#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Inventario de grupos AMP y tags Tenable para mapear reportes.

Este script solo extrae catálogos:
- AMP: grupos disponibles (name/guid).
- Tenable: etiquetas disponibles (category/value/uuid si viene en la API).

Salida por defecto:
  group_inventory/YYYYMMDD_HHMMSS/
    amp_groups.csv
    amp_groups.json
    tenable_tags.csv
    tenable_tags.json
    resumen.txt

Credenciales hardcodeadas para pruebas, alineadas con chido.py.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib import error, parse, request
import base64
import time



# =========================================================
# Credenciales hardcodeadas para pruebas
# =========================================================
AMP_BASE_URL = "https://api.amp.cisco.com/v1"
AMP_CLIENT_ID = "1353f210ba2ab4201857"
AMP_API_KEY = "b03af0dc-1a2f-43ed-83f1-344900b2e322"

TENABLE_BASE_URL = "https://cloud.tenable.com"
TENABLE_ACCESS_KEY = "76513a120af06326a8d04ac756dbe98d1ef799a1fdbfad3d27bfd123c6f03394"
TENABLE_SECRET_KEY = "aac0c8240391ed6107c550eb679ddf0d060083024809b0d6b236bc91e9e99650"

DEFAULT_TENABLE_CATEGORIES = (
    "Omnilife de Mexico",
    "Paises",
    "Razón Social",
)

DEFAULT_OUTPUT_ROOT = Path("group_inventory")
HTTP_TIMEOUT = 90


# =========================================================
# Utilidades
# =========================================================
def norm(text: str) -> str:
    text = (text or "").strip().lower()
    replacements = {
        "á": "a",
        "é": "e",
        "í": "i",
        "ó": "o",
        "ú": "u",
        "ü": "u",
        "ñ": "n",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def safe_fs_name(text: str) -> str:
    text = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "_", (text or "").strip())
    text = re.sub(r"\s+", " ", text).strip().rstrip(". ")
    return text or "unnamed"


def split_categories(raw: Optional[str]) -> Optional[set[str]]:
    if raw is None:
        return {norm(x) for x in DEFAULT_TENABLE_CATEGORIES}
    raw = raw.strip()
    if not raw or raw.lower() in {"all", "todos", "todas", "*"}:
        return None
    return {norm(x) for x in re.split(r"[,;]", raw) if x.strip()}


def request_json_with_retry(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    retries: int = 4,
) -> Tuple[int, Dict[str, Any], str]:
    if params:
        query = parse.urlencode(params)
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}{query}"

    req_headers = dict(headers or {})
    req_headers.setdefault("Accept", "application/json")

    last_status = 0
    last_text = ""
    for attempt in range(1, retries + 1):
        req = request.Request(url, method=method, headers=req_headers)
        try:
            with request.urlopen(req, timeout=HTTP_TIMEOUT) as response:
                raw = response.read().decode("utf-8", errors="replace")
                status = int(response.status)
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            status = int(exc.code)
        except error.URLError as exc:
            if attempt < retries:
                wait_s = attempt * 2
                print(f"[WARN] {method} {url} -> error de conexión: {exc}; reintentando en {wait_s}s...")
                time.sleep(wait_s)
                continue
            raise RuntimeError(f"No se pudo conectar con {url}: {exc}") from exc

        last_status = status
        last_text = raw
        if status not in (429, 500, 502, 503, 504):
            payload = json.loads(raw) if raw.strip() else {}
            if isinstance(payload, dict):
                return status, payload, raw
            return status, {"data": payload}, raw

        if attempt < retries:
            wait_s = attempt * 2
            print(f"[WARN] {method} {url} -> HTTP {status}; reintentando en {wait_s}s...")
            time.sleep(wait_s)

    payload = json.loads(last_text) if last_text.strip() else {}
    if isinstance(payload, dict):
        return last_status, payload, last_text
    return last_status, {"data": payload}, last_text


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def pick_first(data: Dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = data.get(key)
        if value is not None:
            text = str(value).strip()
            if text:
                return text
    return ""


# =========================================================
# AMP
# =========================================================
def fetch_amp_groups() -> List[Dict[str, str]]:
    token = base64.b64encode(f"{AMP_CLIENT_ID}:{AMP_API_KEY}".encode("utf-8")).decode("ascii")
    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {token}",
        "User-Agent": "amp-tenable-group-inventory/1.0",
    }

    groups: List[Dict[str, str]] = []
    seen: set[str] = set()
    limit = 500
    offset = 0

    while True:
        url = f"{AMP_BASE_URL.rstrip('/')}/groups"
        status, payload, raw = request_json_with_retry("GET", url, headers=headers, params={"limit": limit, "offset": offset})
        if status >= 300:
            raise RuntimeError(f"AMP GET /groups falló: HTTP {status} {raw[:500]}")
        data = payload.get("data") if isinstance(payload, dict) else []
        if not isinstance(data, list):
            data = []

        before = len(groups)
        for item in data:
            if not isinstance(item, dict):
                continue
            name = pick_first(item, ("name", "group_name")) or "Unknown"
            guid = pick_first(item, ("guid", "group_guid", "id"))
            key = guid or norm(name)
            if key in seen:
                continue
            seen.add(key)
            groups.append({
                "name": name,
                "guid": guid,
                "normalized_name": norm(name),
            })

        if len(data) < limit or len(groups) == before:
            break
        offset += limit

    return sorted(groups, key=lambda row: norm(row["name"]))


# =========================================================
# Tenable
# =========================================================
def tenable_headers() -> Dict[str, str]:
    return {
        "X-ApiKeys": f"accessKey={TENABLE_ACCESS_KEY}; secretKey={TENABLE_SECRET_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "amp-tenable-group-inventory/1.0",
    }


def fetch_tenable_tags(allowed_categories: Optional[set[str]]) -> List[Dict[str, str]]:
    url = f"{TENABLE_BASE_URL.rstrip('/')}/tags/values"
    status, payload, raw = request_json_with_retry("GET", url, headers=tenable_headers())
    if status >= 300:
        raise RuntimeError(f"Tenable GET /tags/values falló: HTTP {status} {raw[:500]}")
    values = payload.get("values") if isinstance(payload, dict) else []
    if not isinstance(values, list):
        values = []

    tags: List[Dict[str, str]] = []
    seen: set[Tuple[str, str]] = set()
    for item in values:
        if not isinstance(item, dict):
            continue
        category = pick_first(item, ("category_name", "category", "categoryName"))
        value = pick_first(item, ("value", "tag_value", "value_name", "name"))
        if not category or not value:
            continue
        if allowed_categories is not None and norm(category) not in allowed_categories:
            continue

        key = (norm(category), norm(value))
        if key in seen:
            continue
        seen.add(key)
        tags.append({
            "category": category,
            "value": value,
            "category_uuid": pick_first(item, ("category_uuid", "category_id", "categoryId")),
            "value_uuid": pick_first(item, ("uuid", "id", "value_uuid", "tag_value_uuid", "value_id")),
            "normalized_category": norm(category),
            "normalized_value": norm(value),
        })

    return sorted(tags, key=lambda row: (norm(row["category"]), norm(row["value"])))


# =========================================================
# Presentación / salida
# =========================================================
def print_amp_groups(groups: Sequence[Dict[str, str]]) -> None:
    print("\n====================")
    print(f"AMP groups ({len(groups)})")
    print("====================")
    for row in groups:
        guid = row.get("guid") or "sin-guid"
        print(f"- {row.get('name', '')} | {guid}")


def print_tenable_tags(tags: Sequence[Dict[str, str]]) -> None:
    print("\n====================")
    print(f"Tenable tags ({len(tags)})")
    print("====================")
    current_category = None
    for row in tags:
        category = row.get("category", "")
        if category != current_category:
            current_category = category
            print(f"\n[{category}]")
        print(f"- {row.get('value', '')}")


def write_summary(path: Path, amp_groups: Sequence[Dict[str, str]], tenable_tags: Sequence[Dict[str, str]]) -> None:
    categories: Dict[str, int] = {}
    for tag in tenable_tags:
        category = tag.get("category", "") or "sin-categoria"
        categories[category] = categories.get(category, 0) + 1

    lines = [
        "Inventario AMP / Tenable",
        f"Generado UTC: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"AMP groups: {len(amp_groups)}",
        f"Tenable tags: {len(tenable_tags)}",
        "",
        "Tenable tags por categoría:",
    ]
    for category, count in sorted(categories.items(), key=lambda item: norm(item[0])):
        lines.append(f"- {category}: {count}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extrae solo el inventario de grupos AMP y tags Tenable para preparar el mapeo de reportes."
    )
    parser.add_argument(
        "--tenable-categories",
        default=",".join(DEFAULT_TENABLE_CATEGORIES),
        help=(
            "Categorías Tenable separadas por coma/semicolon. "
            "Usa 'all' para traer todas. Default: %(default)s"
        ),
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Carpeta de salida. Default: group_inventory/<timestamp>",
    )
    parser.add_argument("--skip-amp", action="store_true", help="No consulta AMP.")
    parser.add_argument("--skip-tenable", action="store_true", help="No consulta Tenable.")
    parser.add_argument("--quiet", action="store_true", help="No imprime el listado completo en consola.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.out_dir) if args.out_dir else DEFAULT_OUTPUT_ROOT / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    allowed_categories = split_categories(args.tenable_categories)
    amp_groups: List[Dict[str, str]] = []
    tenable_tags: List[Dict[str, str]] = []

    errors: List[str] = []

    if not args.skip_amp:
        print("[INFO] Consultando grupos AMP...")
        try:
            amp_groups = fetch_amp_groups()
            if not args.quiet:
                print_amp_groups(amp_groups)
        except Exception as exc:
            errors.append(f"AMP: {exc}")
            print(f"[ERR] No se pudo consultar AMP: {exc}")
        write_csv(out_dir / "amp_groups.csv", amp_groups, ("name", "guid", "normalized_name"))
        write_json(out_dir / "amp_groups.json", amp_groups)

    if not args.skip_tenable:
        cats_label = "todas" if allowed_categories is None else ", ".join(args.tenable_categories.split(","))
        print(f"[INFO] Consultando tags Tenable (categorías: {cats_label})...")
        try:
            tenable_tags = fetch_tenable_tags(allowed_categories)
            if not args.quiet:
                print_tenable_tags(tenable_tags)
        except Exception as exc:
            errors.append(f"Tenable: {exc}")
            print(f"[ERR] No se pudo consultar Tenable: {exc}")
        write_csv(
            out_dir / "tenable_tags.csv",
            tenable_tags,
            ("category", "value", "category_uuid", "value_uuid", "normalized_category", "normalized_value"),
        )
        write_json(out_dir / "tenable_tags.json", tenable_tags)

    write_summary(out_dir / "resumen.txt", amp_groups, tenable_tags)

    print("\n[DONE] Inventario generado:")
    print(f"- {out_dir / 'amp_groups.csv'}")
    print(f"- {out_dir / 'tenable_tags.csv'}")
    print(f"- {out_dir / 'resumen.txt'}")
    if errors:
        print("\n[WARN] Hubo fuentes que no se pudieron consultar:")
        for item in errors:
            print(f"- {item}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
