#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import calendar
import os
import re
import sys
import tempfile
import zipfile
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

BASE_DIR = Path(__file__).resolve().parent
BASE_OUTPUT_DIR = BASE_DIR / "reportes_finales_docx"
REPORT_PERIOD = ""
REPORT_PERIOD_DOCX = ""
CURRENT_MONTH_FOLDER = datetime.now().strftime("%Y-%m")
OUTPUT_DIR = BASE_OUTPUT_DIR / CURRENT_MONTH_FOLDER

AMP_ALLOWED_GROUPS_OVERRIDE: Optional[set[str]] = None
TENABLE_ALLOWED_TARGETS_OVERRIDE: Optional[set[tuple[str, str]]] = None

TEMPLATE_ENTITY_NAME = "Argentina"
TEMPLATE_PERIOD_TEXT: Optional[str] = "Febrero 2026"
REPLACE_TEXT_INSIDE_DOCX = True

DOCX_IMAGE_MAP: Dict[str, Tuple[str, str]] = {
    "word/media/image4.png": ("amp", "compromises.png"),
    "word/media/image5.png": ("amp", "threats.png"),
    "word/media/image6.png": ("amp", "devices.png"),
    "word/media/image8.png": ("tenable", "03_vulns_severity.png"),
    "word/media/image9.png": ("tenable", "04_vulns_top10.png"),
    "word/media/image10.png": ("tenable", "05_vulns_spotlight.png"),
    "word/media/image11.png": ("tenable", "identity_exposure_donuts_4k.png"),
    "word/media/image12.png": ("tenable", "01_cis_controls_by_asset.png"),
    "word/media/image13.png": ("tenable", "02_cis_controls_totals.png"),
    "word/media/image14.png": ("tenable", "01_audits_list_4k.png"),
    "word/media/image15.png": ("tenable", "02_audit_detail_4k.png"),
}

@dataclass(frozen=True)
class Target:
    display_name: str
    amp_name: str
    tenable_category: str
    tenable_value: str
    output_filename: Optional[str] = None

TARGETS: Tuple[Target, ...] = (
    Target("Argentina", "ARGENTINA", "Omnilife", "Argentina"),
    Target("Bolivia", "BOLIVIA", "Omnilife", "Bolivia"),
    Target("Brasil", "BRASIL", "Omnilife", "Brasil"),
    Target("Chile", "CHILE", "Omnilife", "Chile"),
    Target("Colombia", "COLOMBIA", "Omnilife", "Colombia-Todos"),
    Target("Costa Rica", "COSTA RICA", "Omnilife", "Costa Rica"),
    Target("Ecuador", "ECUADOR", "Omnilife", "Ecuador"),
    Target("El Salvador", "EL SALVADOR", "Omnilife", "El Salvador"),
    Target("España", "ESPAÑA", "Omnilife", "España"),
    Target("Estados Unidos", "USA", "Omnilife", "Estados Unidos"),
    Target("Guatemala", "GUATEMALA", "Omnilife", "Guatemala"),
    Target("Nicaragua", "NICARAGUA", "Omnilife", "Nicaragua"),
    Target("Panamá", "PANAMA", "Omnilife", "Panamá"),
    Target("Paraguay", "PARAGUAY", "Omnilife", "Paraguay"),
    Target("Perú", "PERU", "Omnilife", "Perú"),
    Target("República Dominicana", "Republica Dominicana", "Omnilife", "Republica Dominicana", output_filename="Republica Dominicana_servicios de ciberseguridad"),
    Target("Rusia", "RUSIA", "Omnilife", "Rusia"),
    Target("Uruguay", "URUGUAY", "Omnilife", "Uruguay"),
    Target("Arte y Cultura", "Arte y Cultura Omnilife A.C", "Razón Social", "Arte y Cultura (Museo JV)"),
    Target("Consorcio VAV", "Consorcio Vav, S.A. de C.V", "Razón Social", "Consorcio VAV"),
    Target("Educare", "Educare", "Razón Social", "Educare"),
    Target("Fundación Jorge Vergara", "Fundación Jorge vergara, A.C", "Razón Social", "Fundación Jorge Vergara", output_filename="Fundacion Jorge Vergara_servicios de ciberseguridad"),
    Target("OML Seguros", "OML Agente de Seguros y de Fianzas, S.A. de C.V", "Razón Social", "OML Seguros"),
    Target("Omnia de Guadalajara", "Omnia de Guadalajara, S.A. de C.V", "Razón Social", "Omnia de Guadalajara"),
    Target("Omnidata Internacional", "Omnidata Internacional", "Razón Social", "Omnidata Internacional"),
    Target("Omnihumana", "Omnihumana S.A. de C.V", "Razón Social", "Omnihumana"),
    Target("Omnilife de México", "Omnilife de México S.A de C.V", "Razón Social", "Omnilife de México"),
    Target("Omnilife Manufactura", "Omnilife Manufactura", "Razón Social", "Omnilife Manufactura"),
    Target("Omnipromotora", "Omni promotora de Negocios SA", "Razón Social", "Omnipromotora"),
    Target("Omnisky", "Omnisky SA de CV", "Razón Social", "Omnisky"),
    Target("Planeta Morado", "Planeta Morado , A.C", "Razón Social", "Planeta Morado"),
    Target("Seytú", "Seytu Cosmética, S.A. de C.V", "Razón Social", "Seytú", output_filename="Seytu_servicios de ciberseguridad"),
    Target("Templo Mayor", "Templo Mayor de Chivas, A.C", "Razón Social", "Templo Mayor"),
    Target("Transur", "Transur, S.A. de C.V", "Razón Social", "Transur"),
)


def norm(s: str) -> str:
    s = (s or "").strip().lower()
    replacements = {"á": "a", "é": "e", "í": "i", "ó": "o", "ú": "u", "ü": "u", "ñ": "n"}
    for a, b in replacements.items():
        s = s.replace(a, b)
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def safe_name(s: str) -> str:
    s = re.sub(r'[<>:"/\|?*\x00-]', "_", (s or "").strip())
    s = re.sub(r"\s+", " ", s).strip().rstrip(". ")
    return s or "unnamed"


def output_filename_for(target: Target) -> str:
    base = target.output_filename or f"{target.display_name}_servicios de ciberseguridad"
    if REPORT_PERIOD.strip():
        return f"{safe_name(base)}_{REPORT_PERIOD}.docx"
    return f"{safe_name(base)}.docx"


def format_period_for_docx(report_period: str, *, manual_month_year: bool) -> str:
    months = [
        "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
        "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre",
    ]
    m = re.fullmatch(r"(\d{4})-(\d{2})", (report_period or "").strip())
    if m:
        year = int(m.group(1))
        month = int(m.group(2))
        if 1 <= month <= 12:
            return f"{months[month - 1]} {year}"
    if manual_month_year:
        return report_period
    return "Últimos 30 días"


def cover_entity_name(target: Target) -> str:
    name = (target.display_name or target.output_filename or target.tenable_value or target.amp_name or "").strip()
    name = re.sub(r"\s*\([^)]*\)", "", name)
    legal_forms = [
        r"\bS\.?\s*A\.?\s*(?:DE|de)\s*C\.?\s*V\.?\b",
        r"\bS\.?\s*A\.?\b",
        r"\bA\.?\s*C\.?\b",
        r"\bSA\s+DE\s+CV\b",
        r"\bSA\s+DE\s+C\.?V\.?\b",
    ]
    for pat in legal_forms:
        name = re.sub(pat, "", name, flags=re.IGNORECASE)
    name = re.sub(r"\s*,\s*", " ", name)
    name = re.sub(r"\s+", " ", name).strip(" ,.-")
    return name or target.display_name


def require_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"No existe {label}: {path}")


def run_amp_unified(workdir: Path, start_utc: datetime, end_utc: datetime, allowed_amp: Optional[set[str]] = None) -> Path:
    global AMP_START_UTC_OVERRIDE, AMP_END_UTC_OVERRIDE, OUTPUT_ROOT, AMP_ALLOWED_GROUPS_OVERRIDE
    old_cwd = Path.cwd()
    old_allowed = AMP_ALLOWED_GROUPS_OVERRIDE
    try:
        os.chdir(workdir)
        AMP_START_UTC_OVERRIDE = start_utc
        AMP_END_UTC_OVERRIDE = end_utc
        AMP_ALLOWED_GROUPS_OVERRIDE = set(allowed_amp) if allowed_amp is not None else None
        OUTPUT_ROOT = os.path.join(os.getcwd(), "amp_reportes_unificado")
        print(f"[DEBUG][AMP] OUTPUT_ROOT configurado en: {OUTPUT_ROOT}")
        amp_main()
    finally:
        AMP_START_UTC_OVERRIDE = None
        AMP_END_UTC_OVERRIDE = None
        AMP_ALLOWED_GROUPS_OVERRIDE = old_allowed
        os.chdir(old_cwd)
    amp_root = workdir / "amp_reportes_unificado"
    require_exists(amp_root, "salida AMP")
    print(f"[DEBUG][AMP] Carpeta raíz AMP generada: {amp_root}")
    return amp_root


def run_tenable_unified(workdir: Path, output_dir: Path, allowed_tenable: Optional[set[tuple[str, str]]] = None) -> Path:
    global TENABLE_ALLOWED_TARGETS_OVERRIDE
    old_cwd = Path.cwd()
    old_env = os.environ.get("TENABLE_REPORTS_OUT_DIR")
    old_allowed = TENABLE_ALLOWED_TARGETS_OVERRIDE
    try:
        TENABLE_ALLOWED_TARGETS_OVERRIDE = set(allowed_tenable) if allowed_tenable is not None else None
        os.environ["TENABLE_REPORTS_OUT_DIR"] = str(output_dir)
        os.chdir(workdir)
        run_all()
    finally:
        TENABLE_ALLOWED_TARGETS_OVERRIDE = old_allowed
        os.chdir(old_cwd)
        if old_env is None:
            os.environ.pop("TENABLE_REPORTS_OUT_DIR", None)
        else:
            os.environ["TENABLE_REPORTS_OUT_DIR"] = old_env
    require_exists(output_dir, "salida Tenable")
    return output_dir


def find_latest_timestamp_dir(root: Path) -> Path:
    if not root.is_dir():
        return root
    children = [p for p in root.iterdir() if p.is_dir()]
    if not children:
        return root
    timestamp_like = [c for c in children if c.name.lower().startswith("unificado_") or re.fullmatch(r"\d{4}-\d{2}", c.name)]
    if timestamp_like:
        return sorted(timestamp_like, key=lambda p: p.stat().st_mtime, reverse=True)[0]
    return root


def list_amp_group_dirs(amp_root: Path) -> Dict[str, Path]:
    out: Dict[str, Path] = {}
    if not amp_root.is_dir():
        return out
    real_root = find_latest_timestamp_dir(amp_root)
    print(f"[DEBUG][AMP] Directorio AMP inspeccionado: {real_root}")
    for child in real_root.iterdir():
        if child.is_dir():
            out[norm(child.name)] = child
    if out:
        print("[DEBUG][AMP] Grupos AMP detectados:")
        for k in sorted(out):
            print(f"  - {k} -> {out[k]}")
    return out


def looks_like_tenable_category_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    name = norm(path.name)
    return name in {"asm", "chivas", "educare", "manufactura mexico", "omnilife", "omnilife de mexico", "razon social", "un"}


def resolve_tenable_base(tenable_root: Path) -> Path:
    if not tenable_root.is_dir():
        return tenable_root
    if any(looks_like_tenable_category_dir(p) for p in tenable_root.iterdir()):
        return tenable_root
    subdirs = [p for p in tenable_root.iterdir() if p.is_dir()]
    if len(subdirs) == 1 and any(looks_like_tenable_category_dir(p) for p in subdirs[0].iterdir()):
        return subdirs[0]
    return tenable_root


def list_tenable_tag_dirs(tenable_root: Path) -> Dict[Tuple[str, str], Path]:
    out: Dict[Tuple[str, str], Path] = {}
    if not tenable_root.is_dir():
        return out
    real_root = resolve_tenable_base(tenable_root)
    for category_dir in real_root.iterdir():
        if not category_dir.is_dir() or not looks_like_tenable_category_dir(category_dir):
            continue
        for value_dir in category_dir.iterdir():
            if value_dir.is_dir():
                out[(norm(category_dir.name), norm(value_dir.name))] = value_dir
    return out


def resolve_amp_dir(target: Target, amp_dirs: Dict[str, Path]) -> Optional[Path]:
    wanted = norm(target.amp_name)
    exact = amp_dirs.get(wanted)
    if exact:
        return exact
    for k, v in amp_dirs.items():
        if wanted in k or k in wanted:
            print(f"[WARN][AMP] Match no exacto para '{target.amp_name}': usando grupo '{k}' -> {v}")
            return v
    return None


def resolve_tenable_dir(target: Target, tenable_dirs: Dict[Tuple[str, str], Path]) -> Optional[Path]:
    return tenable_dirs.get((norm(target.tenable_category), norm(target.tenable_value)))


def collect_images_for_target(target: Target, amp_dir: Optional[Path], tenable_dir: Optional[Path]) -> Tuple[Dict[str, bytes], List[str]]:
    replacements: Dict[str, bytes] = {}
    warnings: List[str] = []
    amp_missing_reported = False
    tenable_missing_reported = False

    for media_path, (source, filename) in DOCX_IMAGE_MAP.items():
        root = amp_dir if source == "amp" else tenable_dir
        if root is None:
            if source == "amp" and not amp_missing_reported:
                warnings.append(f"{target.display_name}: no se encontró carpeta AMP exacta '{target.amp_name}'. Se conservarán imágenes AMP originales.")
                amp_missing_reported = True
            elif source == "tenable" and not tenable_missing_reported:
                warnings.append(f"{target.display_name}: no se encontró carpeta Tenable exacta '{target.tenable_category} -> {target.tenable_value}'. Se conservarán imágenes Tenable originales.")
                tenable_missing_reported = True
            continue

        file_path = root / filename
        if not file_path.is_file():
            warnings.append(f"{target.display_name}: falta {source}/{filename} en '{root}'. Se conserva imagen original.")
            continue
        replacements[media_path] = file_path.read_bytes()

    return replacements, warnings


def inspect_template_media(template_path: Path) -> set[str]:
    media: set[str] = set()
    with zipfile.ZipFile(template_path, "r") as zin:
        for name in zin.namelist():
            if name.startswith("word/media/"):
                media.add(name)
    return media


def fit_image_to_placeholder(source_bytes: bytes, placeholder_bytes: bytes) -> bytes:
    from io import BytesIO
    from PIL import Image  # type: ignore

    src = Image.open(BytesIO(source_bytes)).convert("RGB")
    ph = Image.open(BytesIO(placeholder_bytes))
    target_w, target_h = ph.size
    if target_w <= 0 or target_h <= 0:
        return source_bytes

    ratio = min(target_w / src.width, target_h / src.height)
    new_w = max(1, int(src.width * ratio))
    new_h = max(1, int(src.height * ratio))
    resized = src.resize((new_w, new_h), Image.Resampling.LANCZOS)

    canvas = Image.new("RGB", (target_w, target_h), "white")
    offset_x = (target_w - new_w) // 2
    offset_y = (target_h - new_h) // 2
    canvas.paste(resized, (offset_x, offset_y))

    out = BytesIO()
    canvas.save(out, format="PNG", optimize=True)
    return out.getvalue()


def replace_docx_images(template_path: Path, output_path: Path, replacements: Dict[str, bytes]) -> List[str]:
    missing_slots: List[str] = []
    template_files = inspect_template_media(template_path)
    for slot in replacements:
        if slot not in template_files:
            missing_slots.append(slot)
    with zipfile.ZipFile(template_path, "r") as zin, zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename in replacements:
                source, _ = DOCX_IMAGE_MAP.get(item.filename, ("", ""))
                if source == "amp":
                    data = fit_image_to_placeholder(replacements[item.filename], data)
                else:
                    data = replacements[item.filename]
            zout.writestr(item, data)
    return missing_slots


def replace_text_in_docx_xml(
    docx_path: Path,
    old_entity: str,
    new_entity: str,
    old_period: Optional[str],
    new_period: Optional[str],
) -> dict[str, int]:
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}

    def repl(text: str) -> tuple[str, bool, bool]:
        if not text:
            return text, False, False
        changed_entity = old_entity in text
        updated = text.replace(old_entity, new_entity)
        changed_period = False
        if old_period and new_period and old_period in updated:
            changed_period = True
            updated = updated.replace(old_period, new_period)
        return updated, changed_entity, changed_period

    xml_targets: List[str] = []
    with zipfile.ZipFile(docx_path, "r") as zin:
        for name in zin.namelist():
            if name == "word/document.xml":
                xml_targets.append(name)
            elif re.fullmatch(r"word/header\d+\.xml", name):
                xml_targets.append(name)
            elif re.fullmatch(r"word/footer\d+\.xml", name):
                xml_targets.append(name)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".docx") as tmp:
            tmp_docx = Path(tmp.name)

        changed_xml_files = 0
        changed_paragraphs = 0
        entity_replacements = 0
        period_replacements = 0

        with zipfile.ZipFile(tmp_docx, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename in xml_targets:
                    root = ET.fromstring(data)
                    file_changed = False
                    for para in root.findall(".//w:p", ns):
                        text_nodes = para.findall(".//w:t", ns)
                        if not text_nodes:
                            continue
                        full_text = "".join(node.text or "" for node in text_nodes)
                        new_text, did_entity, did_period = repl(full_text)
                        if new_text != full_text:
                            text_nodes[0].text = new_text
                            for node in text_nodes[1:]:
                                node.text = ""
                            file_changed = True
                            changed_paragraphs += 1
                            if did_entity:
                                entity_replacements += 1
                            if did_period:
                                period_replacements += 1
                    if file_changed:
                        changed_xml_files += 1
                        data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
                zout.writestr(item, data)

    tmp_docx.replace(docx_path)
    return {
        "xml_targets": len(xml_targets),
        "changed_xml_files": changed_xml_files,
        "changed_paragraphs": changed_paragraphs,
        "entity_replacements": entity_replacements,
        "period_replacements": period_replacements,
    }


def build_report_for_target(target: Target, template_path: Path, output_dir: Path, amp_dirs: Dict[str, Path], tenable_dirs: Dict[Tuple[str, str], Path]) -> Tuple[Optional[Path], List[str]]:
    amp_dir = resolve_amp_dir(target, amp_dirs)
    tenable_dir = resolve_tenable_dir(target, tenable_dirs)
    if amp_dir:
        for fname in ("compromises.png", "threats.png", "devices.png"):
            fpath = amp_dir / fname
            print(f"[DEBUG][AMP] {target.display_name} -> {fpath} {'[OK]' if fpath.is_file() else '[MISSING]'}")
    replacements, warnings = collect_images_for_target(target, amp_dir, tenable_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / output_filename_for(target)
    missing_slots = replace_docx_images(template_path, out_file, replacements)
    for slot in missing_slots:
        warnings.append(f"{target.display_name}: el template no contiene el slot '{slot}'. Revisa DOCX_IMAGE_MAP contra la plantilla actual.")
    if REPLACE_TEXT_INSIDE_DOCX:
        text_stats = replace_text_in_docx_xml(
            out_file,
            TEMPLATE_ENTITY_NAME,
            cover_entity_name(target),
            TEMPLATE_PERIOD_TEXT,
            REPORT_PERIOD_DOCX or None,
        )
        print(
            "[DEBUG][DOCX] Reemplazo XML "
            f"(target={target.display_name}) -> xml_objetivo={text_stats['xml_targets']}, "
            f"xml_modificados={text_stats['changed_xml_files']}, "
            f"parrafos_modificados={text_stats['changed_paragraphs']}, "
            f"entidad_reemplazos={text_stats['entity_replacements']}, "
            f"fecha_reemplazos={text_stats['period_replacements']}"
        )
        if text_stats["entity_replacements"] > 0:
            print(f"[DEBUG][DOCX] Entidad reemplazada correctamente para '{target.display_name}'.")
        if text_stats["period_replacements"] > 0:
            print(f"[DEBUG][DOCX] Fecha reemplazada correctamente para '{target.display_name}': '{REPORT_PERIOD_DOCX}'.")
        print("[DEBUG][DOCX] Confirmación: NO se usó python-docx para guardar el archivo final.")
    return out_file, warnings


def filter_targets(targets: Sequence[Target], only: Optional[Sequence[str]]) -> List[Target]:
    if not only:
        return list(targets)
    wanted = {norm(x) for x in only}
    out: List[Target] = []
    for t in targets:
        names = {norm(t.display_name), norm(t.amp_name), norm(t.tenable_value), norm(t.output_filename or "")}
        if names & wanted:
            out.append(t)
    return out


def build_allowed_target_sets(selected_targets: Sequence[Target]) -> tuple[set[str], set[tuple[str, str]]]:
    allowed_amp = {norm(t.amp_name) for t in selected_targets}
    allowed_tenable = {(norm(t.tenable_category), norm(t.tenable_value)) for t in selected_targets}
    return allowed_amp, allowed_tenable


def dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _read_key() -> str:
    if os.name == "nt":
        import msvcrt
        while True:
            ch = msvcrt.getch()
            if ch in (b"\xe0", b"\x00"):
                ch2 = msvcrt.getch()
                if ch2 == b"H":
                    return "UP"
                if ch2 == b"P":
                    return "DOWN"
            elif ch in (b"\r", b"\n"):
                return "ENTER"
    else:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                nxt = sys.stdin.read(2)
                if nxt == "[A":
                    return "UP"
                if nxt == "[B":
                    return "DOWN"
            if ch in ("\r", "\n"):
                return "ENTER"
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return ""


def _interactive_select(title: str, options: List[str]) -> str:
    if not options:
        raise RuntimeError("No hay opciones disponibles")
    idx = 0
    while True:
        print("\x1b[2J\x1b[H", end="")
        print(title)
        print("Usa ↑/↓ y Enter.\n")
        for i, opt in enumerate(options):
            prefix = "➤" if i == idx else " "
            print(f"{prefix} {opt}")
        key = _read_key()
        if key == "UP":
            idx = (idx - 1) % len(options)
        elif key == "DOWN":
            idx = (idx + 1) % len(options)
        elif key == "ENTER":
            return options[idx]


def choose_template_interactive(base_dir: Path) -> Path:
    docx_files = sorted([p.name for p in base_dir.iterdir() if p.is_file() and p.suffix.lower() == ".docx"])
    if not docx_files:
        raise RuntimeError("No se encontraron plantillas .docx en el directorio base.")
    selected = _interactive_select("Selecciona plantilla DOCX", docx_files)
    return base_dir / selected


def choose_period_interactive() -> Tuple[datetime, datetime, str, str, bool]:
    mode = _interactive_select("Selecciona rango de tiempo", ["Últimos 30 días", "Elegir mes y año manualmente"])
    now = datetime.now(timezone.utc)
    if mode == "Últimos 30 días":
        start = now - timedelta(days=30)
        end = now
        period = f"{start.strftime('%Y-%m-%d')}_a_{end.strftime('%Y-%m-%d')}"
        return start, end, period, now.strftime("%Y-%m"), False

    months = ["Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio", "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"]
    month = months.index(_interactive_select("Selecciona mes", months)) + 1
    years = [str(y) for y in range(now.year, now.year - 10, -1)]
    year = int(_interactive_select("Selecciona año", years))

    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end_day = calendar.monthrange(year, month)[1]
    end = datetime(year, month, end_day, 23, 59, 59, tzinfo=timezone.utc)
    period = f"{year}-{month:02d}"
    return start, end, period, period, True


def main(argv: Optional[Sequence[str]] = None) -> int:
    global OUTPUT_DIR, REPORT_PERIOD, REPORT_PERIOD_DOCX

    parser = argparse.ArgumentParser(description="Genera imágenes AMP/Tenable, arma DOCX y limpia temporales.")
    parser.add_argument("--solo", nargs="+", help="Procesa únicamente estas entidades.")
    parser.add_argument("--template", help="Ruta de template DOCX para modo no interactivo.")
    args = parser.parse_args(argv)

    selected_targets = filter_targets(TARGETS, args.solo)
    if not selected_targets:
        print("[ERR] No hubo coincidencias en TARGETS para --solo.")
        return 2

    allowed_amp, allowed_tenable = build_allowed_target_sets(selected_targets)

    if args.template:
        template_docx = Path(args.template)
        now = datetime.now(timezone.utc)
        start_utc = now - timedelta(days=30)
        end_utc = now
        REPORT_PERIOD = now.strftime("%Y-%m")
        month_folder = now.strftime("%Y-%m")
        REPORT_PERIOD_DOCX = format_period_for_docx(REPORT_PERIOD, manual_month_year=True)
    else:
        template_docx = choose_template_interactive(BASE_DIR)
        start_utc, end_utc, REPORT_PERIOD, month_folder, manual_month_year = choose_period_interactive()
        REPORT_PERIOD_DOCX = format_period_for_docx(month_folder, manual_month_year=manual_month_year)

    require_exists(template_docx, "TEMPLATE_DOCX")
    template_media = inspect_template_media(template_docx)
    print(f"[DEBUG][DOCX] Template: {template_docx}")
    print(f"[DEBUG][DOCX] REPORT_PERIOD_DOCX: {REPORT_PERIOD_DOCX}")
    print(f"[DEBUG][DOCX] Total media encontrados: {len(template_media)}")
    missing_expected_slots = [slot for slot in DOCX_IMAGE_MAP if slot not in template_media]
    if missing_expected_slots:
        print("[WARN][DOCX] Slots esperados no encontrados en el template actual:")
        for slot in missing_expected_slots:
            print(f"  - {slot} (mapeado a {DOCX_IMAGE_MAP[slot]})")
        print("[WARN][DOCX] Si el DOCX cambió internamente, ajusta DOCX_IMAGE_MAP a los nuevos imageX.png.")

    OUTPUT_DIR = BASE_OUTPUT_DIR / month_folder
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="reportes_amp_tenable_") as tmp:
        tmp_path = Path(tmp)
        amp_workdir = tmp_path / "amp_runner"
        tenable_workdir = tmp_path / "tenable_runner"
        amp_workdir.mkdir(parents=True, exist_ok=True)
        tenable_workdir.mkdir(parents=True, exist_ok=True)

        print(f"[INFO] Temporales en: {tmp_path}")
        print("[INFO] Generando imágenes de AMP...")
        amp_root: Optional[Path] = None
        try:
            amp_root = run_amp_unified(amp_workdir, start_utc, end_utc, allowed_amp=allowed_amp)
        except Exception as e:
            print(f"[WARN] No se pudieron generar imágenes de AMP ({e}). Se continuará con imágenes AMP originales del template.")

        print("[INFO] Generando imágenes de Tenable...")
        tenable_root = tenable_workdir / "tenable_reportes_unificados"
        tenable_root = run_tenable_unified(tenable_workdir, tenable_root, allowed_tenable=allowed_tenable)

        amp_dirs = list_amp_group_dirs(amp_root) if amp_root else {}
        tenable_dirs = list_tenable_tag_dirs(tenable_root)
        print(f"[INFO] Carpetas AMP detectadas: {len(amp_dirs)}")
        if amp_dirs:
            print(f"[DEBUG][AMP] Nombres de grupos AMP detectados (normalizados): {sorted(amp_dirs.keys())}")
        print(f"[INFO] Carpetas Tenable detectadas: {len(tenable_dirs)}")

        generated = 0
        all_warnings: List[str] = []

        for target in selected_targets:
            print(f"[INFO] Generando DOCX para: {target.display_name}")
            out_file, warnings = build_report_for_target(target, template_docx, OUTPUT_DIR, amp_dirs, tenable_dirs)
            all_warnings.extend(warnings)
            if out_file:
                generated += 1
                print(f"[OK] {target.display_name} -> {out_file}")

    print(f"[DONE] DOCX generados: {generated}")
    print(f"[DONE] Carpeta final: {OUTPUT_DIR}")
    all_warnings = dedupe_keep_order(all_warnings)
    if all_warnings:
        print("\n[WARN] Resumen de advertencias:")
        for w in all_warnings:
            print(f" - {w}")
    return 0


# ====================== AMP UNIFICADO (INLINE) ======================

import importlib
import subprocess


def _ensure_dependencies() -> None:
    required = {
        "requests": "requests",
        "PIL": "Pillow",
        "pandas": "pandas",
        "matplotlib": "matplotlib",
    }

    missing = []
    for module_name, package_name in required.items():
        try:
            importlib.import_module(module_name)
        except ImportError:
            missing.append(package_name)

    if not missing:
        return

    print(f"[INFO] Instalando dependencias faltantes: {', '.join(missing)}")
    cmd = [sys.executable, "-m", "pip", "install", *missing]
    try:
        subprocess.check_call(cmd)
    except Exception:
        subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"])
        subprocess.check_call(cmd)


_ensure_dependencies()

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

def _amp_norm_name(s: str) -> str:
    s = (s or "").strip().lower()
    s = "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn")
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()

def _filter_existing_amp_groups(groups: List[Dict[str, str]], allowed_amp: set[str]) -> List[Dict[str, str]]:
    if not allowed_amp:
        return groups
    allowed_norm = {_amp_norm_name(x) for x in allowed_amp if x}
    selected: List[Dict[str, str]] = []
    skipped: List[str] = []
    for g in groups:
        gname = str(g.get("name") or "")
        gnorm = _amp_norm_name(gname)
        if gnorm in allowed_norm or any(gnorm in a or a in gnorm for a in allowed_norm):
            selected.append(g)
        else:
            skipped.append(gname)
    print(f"[DEBUG][AMP] Grupos filtrados ({len(selected)}): {[g.get('name') for g in selected]}")
    if skipped:
        print(f"[DEBUG][AMP] Grupos omitidos por filtro ({len(skipped)}): {skipped[:20]}{'...' if len(skipped) > 20 else ''}")
    return selected

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
def amp_main():
    if "PEGA_AQUI" in AMP_CLIENT_ID or "PEGA_AQUI" in AMP_API_KEY:
        raise SystemExit("Configura AMP_CLIENT_ID y AMP_API_KEY dentro del script (hardcoded para pruebas).")

    amp = AmpClient(AMP_BASE_URL, AMP_CLIENT_ID, AMP_API_KEY)

    now = dt.datetime.now(dt.timezone.utc)
    start_utc = globals().get("AMP_START_UTC_OVERRIDE") or (now - dt.timedelta(days=DAYS_BACK))
    end_utc = globals().get("AMP_END_UTC_OVERRIDE") or now

    ts = now.strftime("%Y%m%d_%H%M%SZ")
    out_root = os.path.join(OUTPUT_ROOT, f"unificado_{ts}")
    ensure_dir(out_root)

    groups = amp.get_groups()
    allowed_amp = globals().get("AMP_ALLOWED_GROUPS_OVERRIDE")
    if allowed_amp is not None:
        before = len(groups)
        groups = _filter_existing_amp_groups(groups, allowed_amp)
        print(f"✅ Groups filtrados por TARGETS existentes: {len(groups)} de {before}")
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



# ====================== TENABLE UNIFICADO (INLINE) ======================



import os
import sys
from types import MappingProxyType
from typing import Dict, Any, Callable, Optional


# =========================================================
# Fuentes embebidas (se ejecutan en namespaces aislados)
# =========================================================
# =========================================================
# 🔐 Credenciales globales (único estándar)
#    Se leen UNA sola vez desde variables de entorno y se
#    inyectan a todos los módulos embebidos.
# =========================================================
TENABLE_BASE_URL = os.getenv("TENABLE_BASE_URL", "https://cloud.tenable.com").strip().rstrip("/")
TENABLE_ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY", "76513a120af06326a8d04ac756dbe98d1ef799a1fdbfad3d27bfd123c6f03394").strip()
TENABLE_SECRET_KEY = os.getenv("TENABLE_SECRET_KEY", "aac0c8240391ed6107c550eb679ddf0d060083024809b0d6b236bc91e9e99650").strip()

MODULE_SOURCES: Dict[str, str] = {
    "cis_audit_charts": '#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n\nimport os\nimport re\nimport json\nimport time\nimport gzip\nfrom collections import defaultdict, Counter\nfrom typing import Any, Dict, List, Tuple, Optional\n\nimport requests\nimport pandas as pd\nimport matplotlib\nmatplotlib.use("Agg")\nimport matplotlib.pyplot as plt\n\n\n# =========================================================\n# CONFIG (HARDCODED PARA PRUEBAS)\n# =========================================================\nOUT_DIR = "tenable_cis_tag_reports"\n\n# Export\nNUM_FINDINGS_PER_CHUNK = 5000\nPOLL_INTERVAL_SEC = 3\nPOLL_TIMEOUT_SEC = 1200  # 20 min\n\n# Imágenes\nDPI = 300\nMAX_ASSETS_IN_TABLE = 25  # tabla tipo dashboard (top N por FAILED)\n\n# Colores (similar Tenable)\nCOLOR_FAILED = "#d9534f"\nCOLOR_PASSED = "#5cb85c"\nCOLOR_WARNING = "#f0ad4e"\n\nWANTED_RESULTS = {"FAILED", "PASSED", "WARNING"}\n\n# Opcional: guardar export completo para reprocesar offline\nSAVE_RAW_JSONL_GZ = False\nRAW_JSONL_GZ_PATH = os.path.join(OUT_DIR, "compliance_export_all.jsonl.gz")\n\n# Opcional: reprocesar desde archivo (sin llamar API)\nINPUT_JSONL_GZ = None  # ejemplo: "tenable_cis_tag_reports/compliance_export_all.jsonl.gz"\n\n\n# =========================================================\n# Helpers\n# =========================================================\ndef headers() -> Dict[str, str]:\n    return {\n        "X-ApiKeys": f"accessKey={TENABLE_ACCESS_KEY}; secretKey={TENABLE_SECRET_KEY}",\n        "Accept": "application/json",\n        "Content-Type": "application/json",\n        "User-Agent": "cis-audit-postprocess/1.0",\n    }\n\n\ndef safe_fs_name(s: str) -> str:\n    s = (s or "").strip()\n    s = re.sub(r\'[<>:"/\\\\|?*\\x00-\\x1F]\', "_", s)\n    s = re.sub(r"\\s+", " ", s).strip()\n    s = s.rstrip(". ")\n    return s[:160] if len(s) > 160 else (s if s else "unnamed")\n\n\ndef request_retry(session: requests.Session, method: str, path: str, **kwargs) -> requests.Response:\n    url = TENABLE_BASE_URL.rstrip("/") + path\n    last = None\n    for i in range(1, 6):\n        r = session.request(method, url, timeout=120, **kwargs)\n        last = r\n        if r.status_code in (429, 500, 502, 503, 504):\n            time.sleep(i * 2)\n            continue\n        return r\n    return last\n\n\ndef try_parse_payload(content: bytes) -> Any:\n    if not content:\n        return None\n\n    # gzip?\n    if len(content) >= 2 and content[0] == 0x1F and content[1] == 0x8B:\n        try:\n            content = gzip.decompress(content)\n        except Exception:\n            pass\n\n    s = content.decode("utf-8", errors="replace").strip()\n    if not s:\n        return None\n\n    # JSON normal\n    if s[0] in "{[":\n        try:\n            return json.loads(s)\n        except Exception:\n            pass\n\n    # NDJSON\n    out = []\n    for line in s.splitlines():\n        line = line.strip()\n        if not line:\n            continue\n        try:\n            out.append(json.loads(line))\n        except Exception:\n            continue\n    return out if out else None\n\n\ndef extract_records(payload: Any) -> List[Dict[str, Any]]:\n    if payload is None:\n        return []\n    if isinstance(payload, list):\n        return [x for x in payload if isinstance(x, dict)]\n    if isinstance(payload, dict):\n        for k in ("findings", "items", "data", "results", "objects", "records"):\n            v = payload.get(k)\n            if isinstance(v, list):\n                return [x for x in v if isinstance(x, dict)]\n        return [payload]\n    return []\n\n\ndef pick_result(rec: Dict[str, Any]) -> Optional[str]:\n    for k in ("status", "result", "compliance_result", "check_result", "state"):\n        v = rec.get(k)\n        if isinstance(v, str) and v.strip():\n            return v.strip().upper()\n\n    for parent in ("compliance", "check", "finding"):\n        v = rec.get(parent)\n        if isinstance(v, dict):\n            for k in ("status", "result", "compliance_result", "state"):\n                vv = v.get(k)\n                if isinstance(vv, str) and vv.strip():\n                    return vv.strip().upper()\n    return None\n\n\ndef normalize_result(r: Optional[str]) -> Optional[str]:\n    if not r:\n        return None\n    r = r.upper().strip()\n    if r in ("PASS", "PASSED", "SUCCESS"):\n        return "PASSED"\n    if r in ("FAIL", "FAILED"):\n        return "FAILED"\n    if r in ("WARN", "WARNING"):\n        return "WARNING"\n    if r in ("NOTAPPLICABLE", "NOT_APPLICABLE", "N/A", "NA"):\n        return None\n    if r in ("ERROR", "INFO"):\n        return "WARNING"\n    return None\n\n\ndef extract_asset_tags(rec: Dict[str, Any]) -> List[Tuple[str, str]]:\n    tags = []\n    asset = rec.get("asset")\n    if isinstance(asset, dict):\n        tlist = asset.get("tags")\n        if isinstance(tlist, list):\n            for t in tlist:\n                if not isinstance(t, dict):\n                    continue\n                cat = t.get("category") or t.get("category_name") or t.get("categoryName")\n                val = t.get("value") or t.get("value_name") or t.get("valueName")\n                if isinstance(cat, str) and isinstance(val, str) and cat.strip() and val.strip():\n                    tags.append((cat.strip(), val.strip()))\n    return tags\n\n\n# =========================================================\n# ASSET NAME NORMALIZATION (quita DOMINIO\\ y $)\n# =========================================================\ndef normalize_asset_display_name(name: str) -> str:\n    """\n    Limpia nombres tipo:\n      OMNILIFE\\\\HOSTNAME$  -> HOSTNAME\n      OMNILIFE\\\\HOSTNAME   -> HOSTNAME\n      hostname$            -> hostname\n    """\n    if not name:\n        return "unknown-asset"\n\n    s = str(name).strip()\n\n    # DOMINIO\\HOSTNAME$ -> HOSTNAME$\n    if "\\\\" in s:\n        s = s.split("\\\\")[-1].strip()\n\n    # Quitar $ final (cuenta de equipo AD)\n    if s.endswith("$"):\n        s = s[:-1].strip()\n\n    return s if s else "unknown-asset"\n\n\ndef pick_asset_name(rec: Dict[str, Any]) -> str:\n    asset = rec.get("asset")\n    if isinstance(asset, dict):\n        for k in ("fqdn", "hostname", "netbios_name", "name", "display_name"):\n            v = asset.get(k)\n            if isinstance(v, str) and v.strip():\n                return normalize_asset_display_name(v)\n\n        for k in ("ipv4", "ip"):\n            v = asset.get(k)\n            if isinstance(v, str) and v.strip():\n                return v.strip()\n            if isinstance(v, list) and v:\n                return str(v[0])\n\n        v = asset.get("uuid") or asset.get("id")\n        if isinstance(v, str) and v.strip():\n            return v.strip()\n\n    for k in ("fqdn", "hostname", "netbios_name", "name", "ipv4", "ip", "asset_uuid"):\n        v = rec.get(k)\n        if isinstance(v, str) and v.strip():\n            return normalize_asset_display_name(v)\n\n    return "unknown-asset"\n\n\n# =========================================================\n# Tenable API\n# =========================================================\ndef list_tag_values(session: requests.Session) -> List[Tuple[str, str]]:\n    r = request_retry(session, "GET", "/tags/values", headers=headers())\n    r.raise_for_status()\n    data = r.json()\n    values = data.get("values") if isinstance(data, dict) else None\n    if not isinstance(values, list):\n        return []\n    out = []\n    for item in values:\n        if not isinstance(item, dict):\n            continue\n        cat = item.get("category_name") or item.get("category")\n        val = item.get("value")\n        if isinstance(cat, str) and isinstance(val, str) and cat.strip() and val.strip():\n            out.append((cat.strip(), val.strip()))\n    return sorted(set(out))\n\n\ndef create_compliance_export_all(session: requests.Session) -> str:\n    payload_variants = [\n        {"num_findings": NUM_FINDINGS_PER_CHUNK},\n        {"num_findings": NUM_FINDINGS_PER_CHUNK, "filters": {}},\n        {"filters": {}},\n        {},\n    ]\n    last_text = None\n    for body in payload_variants:\n        r = request_retry(session, "POST", "/compliance/export", headers=headers(), json=body)\n        if r.status_code == 200:\n            resp = r.json()\n            export_uuid = resp.get("export_uuid") or resp.get("uuid") or resp.get("id")\n            if export_uuid:\n                return export_uuid\n            raise RuntimeError(f"No encontré export_uuid en respuesta: {resp}")\n        last_text = f"[{r.status_code}] {r.text}"\n    raise RuntimeError(f"No se pudo crear export global. Último error: {last_text}")\n\n\ndef poll_chunks(session: requests.Session, export_uuid: str) -> List[int]:\n    start = time.time()\n    chunk_ids: List[int] = []\n\n    while True:\n        r = request_retry(session, "GET", f"/compliance/export/{export_uuid}/status", headers=headers())\n        r.raise_for_status()\n        st = r.json()\n\n        status = (st.get("status") or "").upper()\n\n        ca = st.get("chunks_available")\n        if isinstance(ca, list):\n            for x in ca:\n                try:\n                    chunk_ids.append(int(x))\n                except Exception:\n                    pass\n\n        ch = st.get("chunks")\n        if isinstance(ch, list):\n            for x in ch:\n                if isinstance(x, int):\n                    chunk_ids.append(x)\n                elif isinstance(x, dict):\n                    cid = x.get("id") or x.get("chunk_id")\n                    if isinstance(cid, int):\n                        chunk_ids.append(cid)\n                    elif isinstance(cid, str) and cid.isdigit():\n                        chunk_ids.append(int(cid))\n\n        chunk_ids = sorted(set(chunk_ids))\n\n        if status in ("FINISHED", "CANCELLED", "ERROR") and chunk_ids:\n            return chunk_ids\n\n        if time.time() - start > POLL_TIMEOUT_SEC:\n            if chunk_ids:\n                return chunk_ids\n            raise TimeoutError(f"Timeout esperando chunks. Último status: {st}")\n\n        time.sleep(POLL_INTERVAL_SEC)\n\n\ndef download_chunk(session: requests.Session, export_uuid: str, chunk_id: int) -> List[Dict[str, Any]]:\n    r = request_retry(session, "GET", f"/compliance/export/{export_uuid}/chunks/{chunk_id}", headers=headers())\n    r.raise_for_status()\n    try:\n        payload = r.json()\n    except Exception:\n        payload = try_parse_payload(r.content)\n    return extract_records(payload)\n\n\n# =========================================================\n# Render\n# =========================================================\ndef render_table_png(df: pd.DataFrame, out_png: str, title: str) -> None:\n    if df.empty:\n        fig = plt.figure(figsize=(16, 5), dpi=DPI)\n        plt.axis("off")\n        plt.text(0.5, 0.55, title, ha="center", va="center", fontsize=18, fontweight="bold")\n        plt.text(0.5, 0.35, "NO DATA FOR THIS TAG", ha="center", va="center", fontsize=14)\n        fig.savefig(out_png, bbox_inches="tight", facecolor="white")\n        plt.close(fig)\n        return\n\n    view = df.sort_values(by=["FAILED", "WARNING", "PASSED"], ascending=False).head(MAX_ASSETS_IN_TABLE)\n\n    height = max(6, 0.45 * (len(view) + 2))\n    fig, ax = plt.subplots(figsize=(16, height), dpi=DPI)\n    ax.axis("off")\n    ax.set_title(title, fontsize=16, fontweight="bold", pad=18)\n\n    col_labels = ["Asset", "FAILED", "PASSED", "WARNING"]\n    cell_text = [[idx, int(r.FAILED), int(r.PASSED), int(r.WARNING)] for idx, r in view.iterrows()]\n\n    table = ax.table(\n        cellText=cell_text,\n        colLabels=col_labels,\n        cellLoc="center",\n        colLoc="center",\n        loc="center",\n    )\n    table.auto_set_font_size(False)\n    table.set_fontsize(10)\n    table.scale(1, 1.5)\n\n    header_colors = {1: COLOR_FAILED, 2: COLOR_PASSED, 3: COLOR_WARNING}\n    for j in range(4):\n        cell = table[(0, j)]\n        cell.set_text_props(fontweight="bold", color="white" if j in header_colors else "black")\n        cell.set_facecolor(header_colors.get(j, "#e6e6e6"))\n\n    for i in range(len(cell_text) + 1):\n        table[(i, 0)]._width = 0.60\n        table[(i, 1)]._width = 0.13\n        table[(i, 2)]._width = 0.13\n        table[(i, 3)]._width = 0.14\n\n    fig.savefig(out_png, bbox_inches="tight", facecolor="white")\n    plt.close(fig)\n\n\ndef render_totals_png(totals: Counter, out_png: str, title: str) -> None:\n    failed = int(totals.get("FAILED", 0))\n    passed = int(totals.get("PASSED", 0))\n    warning = int(totals.get("WARNING", 0))\n\n    fig, ax = plt.subplots(figsize=(12, 4.5), dpi=DPI)\n    ax.set_title(title, fontsize=16, fontweight="bold", pad=12)\n    labels = ["FAILED", "PASSED", "WARNING"]\n    values = [failed, passed, warning]\n    colors = [COLOR_FAILED, COLOR_PASSED, COLOR_WARNING]\n\n    bars = ax.barh(labels, values, color=colors)\n    ax.grid(axis="x", linestyle="--", alpha=0.4)\n    ax.set_axisbelow(True)\n    ax.set_xlabel("Checks")\n\n    mx = max(values) if max(values) else 1\n    for b, v in zip(bars, values):\n        ax.text(b.get_width() + mx * 0.01, b.get_y() + b.get_height() / 2, f"{v:,}", va="center", fontsize=12)\n\n    fig.savefig(out_png, bbox_inches="tight", facecolor="white")\n    plt.close(fig)\n\n\n# =========================================================\n# Offline aggregation core\n# =========================================================\ndef aggregate_from_records(\n    records_iter,\n    allowed_tags: Optional[set] = None,\n    raw_writer_gz: Optional[gzip.GzipFile] = None\n):\n    totals_by_tag = defaultdict(Counter)\n    assets_by_tag = defaultdict(lambda: defaultdict(Counter))\n\n    processed = 0\n    counted = 0\n\n    for rec in records_iter:\n        processed += 1\n\n        if raw_writer_gz is not None:\n            raw_writer_gz.write((json.dumps(rec, ensure_ascii=False) + "\\n").encode("utf-8"))\n\n        res = normalize_result(pick_result(rec))\n        if not res or res not in WANTED_RESULTS:\n            continue\n\n        tags = extract_asset_tags(rec)\n        if not tags:\n            continue\n\n        asset = pick_asset_name(rec)\n\n        for (cat, val) in tags:\n            if allowed_tags is not None and (cat, val) not in allowed_tags:\n                continue\n            totals_by_tag[(cat, val)][res] += 1\n            assets_by_tag[(cat, val)][asset][res] += 1\n            counted += 1\n\n        if processed % 20000 == 0:\n            print(f"  ...procesados {processed:,} records | contados {counted:,} (tag-assignments)")\n\n    return totals_by_tag, assets_by_tag\n\n\ndef iter_records_from_api(session: requests.Session):\n    export_uuid = create_compliance_export_all(session)\n    print(f"✅ Export global creado: {export_uuid}")\n\n    chunk_ids = poll_chunks(session, export_uuid)\n    print(f"✅ Chunks a descargar: {len(chunk_ids)} -> {chunk_ids[:10]}{\'...\' if len(chunk_ids)>10 else \'\'}")\n\n    for cid in chunk_ids:\n        recs = download_chunk(session, export_uuid, cid)\n        for r in recs:\n            yield r\n\n\ndef iter_records_from_jsonl_gz(path: str):\n    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:\n        for line in f:\n            line = line.strip()\n            if not line:\n                continue\n            try:\n                yield json.loads(line)\n            except Exception:\n                continue\n\n\n# =========================================================\n# MAIN\n# =========================================================\ndef main():\n    if (not TENABLE_ACCESS_KEY) or (not TENABLE_SECRET_KEY):\n        raise SystemExit("❌ Configura TENABLE_ACCESS_KEY y TENABLE_SECRET_KEY en el script.")\n\n    os.makedirs(OUT_DIR, exist_ok=True)\n\n    session = requests.Session()\n\n    # Tags existentes (para generar outputs aunque un tag tenga 0 data)\n    all_tags = list_tag_values(session) if INPUT_JSONL_GZ is None else None\n\n    if all_tags is None:\n        allowed = None\n        print("ℹ️ Reprocesando offline: tags se derivarán del dataset.")\n    else:\n        allowed = set(all_tags)\n        print(f"✅ Tags detectados (Tenable): {len(all_tags)}")\n\n    raw_writer = None\n    if SAVE_RAW_JSONL_GZ and INPUT_JSONL_GZ is None:\n        raw_writer = gzip.open(RAW_JSONL_GZ_PATH, "wb")\n        print(f"🧾 Guardando dataset completo en: {RAW_JSONL_GZ_PATH}")\n\n    try:\n        if INPUT_JSONL_GZ:\n            records_iter = iter_records_from_jsonl_gz(INPUT_JSONL_GZ)\n        else:\n            records_iter = iter_records_from_api(session)\n\n        print("▶ Agregando por tag (post-proceso)...")\n        totals_by_tag, assets_by_tag = aggregate_from_records(records_iter, allowed_tags=allowed, raw_writer_gz=raw_writer)\n    finally:\n        if raw_writer is not None:\n            raw_writer.close()\n\n    tags_to_output = all_tags if all_tags is not None else sorted(totals_by_tag.keys())\n    print(f"▶ Generando reportes para tags: {len(tags_to_output)}")\n\n    for (cat, val) in tags_to_output:\n        out_path = os.path.join(OUT_DIR, safe_fs_name(cat), safe_fs_name(val))\n        os.makedirs(out_path, exist_ok=True)\n\n        totals = totals_by_tag.get((cat, val), Counter())\n        asset_map = assets_by_tag.get((cat, val), {})\n\n        rows = []\n        for asset_name, c in asset_map.items():\n            rows.append({\n                "Asset": asset_name,\n                "FAILED": int(c.get("FAILED", 0)),\n                "PASSED": int(c.get("PASSED", 0)),\n                "WARNING": int(c.get("WARNING", 0)),\n            })\n\n        df = pd.DataFrame(rows)\n        if not df.empty:\n            df = df.set_index("Asset")\n\n        csv_path = os.path.join(out_path, "cis_controls_by_asset.csv")\n        if df.empty:\n            pd.DataFrame(columns=["Asset", "FAILED", "PASSED", "WARNING"]).to_csv(csv_path, index=False, encoding="utf-8-sig")\n        else:\n            df.reset_index().to_csv(csv_path, index=False, encoding="utf-8-sig")\n\n        title_table = f"Conteo de controles CIS por equipo\\nTag: {cat}:{val}"\n        title_totals = f"CIS Checks Totales\\nTag: {cat}:{val}"\n\n        render_table_png(df, os.path.join(out_path, "01_cis_controls_by_asset.png"), title_table)\n        render_totals_png(totals, os.path.join(out_path, "02_cis_controls_totals.png"), title_totals)\n\n        if (cat, val) in totals_by_tag:\n            print(f"✅ {cat}:{val} -> FAILED={totals.get(\'FAILED\',0):,} PASSED={totals.get(\'PASSED\',0):,} WARNING={totals.get(\'WARNING\',0):,}")\n        else:\n            print(f"⚠️ {cat}:{val} -> sin data")\n\n    print("\\n✅ Listo. Carpeta:", OUT_DIR)\n    if SAVE_RAW_JSONL_GZ and INPUT_JSONL_GZ is None:\n        print("✅ Dataset guardado:", RAW_JSONL_GZ_PATH)\n\n\nif __name__ == "__main__":\n    main()\n',
    "controlesCIS": '#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n\n"""\nTenable VM (cloud.tenable.com) - CIS Host Audits -> 2 imágenes por TAG (AUTO)\n\n✅ Para cada TAG (category=value) detectada:\n  01_audits_list_4k.png   -> Lista estilo Tenable con TOP host audits FAILED + assets de ejemplo\n  02_audit_detail_4k.png  -> Detalle tipo "audit abierto" del audit #1 (más fallos) + Solution + assets\n\n✅ Data:\n  - Tags: GET /tags/values (paginado) + fallback por category_uuid\n  - Findings: POST /compliance/export (global) + descarga chunks\n\nRequisitos:\n  pip install requests pillow\n\nEjecución (PowerShell):\n  $env:TENABLE_ACCESS_KEY="..."\n  $env:TENABLE_SECRET_KEY="..."\n  python .\\controlesCIS_audits_por_tag_v2.py\n\nOpcionales:\n  --only-category "Omnilife"        (puedes repetirlo)\n  --max-tags 50                     (para pruebas)\n  --rows 12                         (filas en tabla)\n  --assets-per-row 3\n"""\n\nfrom __future__ import annotations\n\nimport os\nimport re\nimport json\nimport time\nimport gzip\nimport argparse\nfrom datetime import datetime, timezone\nfrom collections import defaultdict\nfrom typing import Any, Dict, List, Tuple, Optional\n\nimport requests\nfrom PIL import Image, ImageDraw, ImageFont\n\n\n# =========================================================\n# CONFIG\n# =========================================================\nBASE_URL = TENABLE_BASE_URL\n\nIMG_W = 3840\nIMG_H = 2160\n\nNUM_FINDINGS_PER_CHUNK = 5000\nPOLL_INTERVAL_SEC = 3\nPOLL_TIMEOUT_SEC = 1200  # 20 min\n\nONLY_RESULT = {"FAILED"}  # como en Tenable host audits\n\n\n# =========================================================\n# Visual style\n# =========================================================\nCOL_BG = "#F8FAFC"\nCARD_BG = "#FFFFFF"\nBORDER = "#E2E8F0"\nTEXT = "#0F172A"\nMUTED = "#475569"\nMUTED2 = "#64748B"\nHEADER_BG = "#F1F5F9"\nROW_ALT = "#FBFDFF"\nFAIL_RED = "#B91C1C"\n\n\n# =========================================================\n# Helpers\n# =========================================================\ndef headers() -> Dict[str, str]:\n    return {\n        "X-ApiKeys": f"accessKey={TENABLE_ACCESS_KEY}; secretKey={TENABLE_SECRET_KEY}",\n        "Accept": "application/json",\n        "Content-Type": "application/json",\n        "User-Agent": "cis-host-audits-by-tag/2.0",\n    }\n\ndef _norm(s: str) -> str:\n    return (s or "").strip().lower()\n\ndef safe_fs_name(s: str) -> str:\n    s = (s or "").strip()\n    s = re.sub(r\'[<>:"/\\\\|?*\\x00-\\x1F]\', "_", s)\n    s = re.sub(r"\\s+", " ", s).strip()\n    s = s.rstrip(". ")\n    return (s[:160] if len(s) > 160 else s) or "unnamed"\n\ndef request_retry(session: requests.Session, method: str, path: str, **kwargs) -> requests.Response:\n    url = BASE_URL.rstrip("/") + path\n    last = None\n    for i in range(1, 9):\n        r = session.request(method, url, timeout=180, **kwargs)\n        last = r\n        if r.status_code in (429, 500, 502, 503, 504):\n            time.sleep(min(2 * i, 25))\n            continue\n        return r\n    return last  # type: ignore\n\ndef try_parse_payload(content: bytes) -> Any:\n    if not content:\n        return None\n    if len(content) >= 2 and content[0] == 0x1F and content[1] == 0x8B:\n        try:\n            content = gzip.decompress(content)\n        except Exception:\n            pass\n    s = content.decode("utf-8", errors="replace").strip()\n    if not s:\n        return None\n    if s[0] in "{[":\n        try:\n            return json.loads(s)\n        except Exception:\n            pass\n    out = []\n    for line in s.splitlines():\n        line = line.strip()\n        if not line:\n            continue\n        try:\n            out.append(json.loads(line))\n        except Exception:\n            continue\n    return out if out else None\n\ndef extract_records(payload: Any) -> List[Dict[str, Any]]:\n    if payload is None:\n        return []\n    if isinstance(payload, list):\n        return [x for x in payload if isinstance(x, dict)]\n    if isinstance(payload, dict):\n        for k in ("findings", "items", "data", "results", "objects", "records", "values"):\n            v = payload.get(k)\n            if isinstance(v, list) and v and isinstance(v[0], dict):\n                return [x for x in v if isinstance(x, dict)]\n        return [payload]\n    return []\n\ndef normalize_asset_display_name(name: str) -> str:\n    if not name:\n        return "unknown-asset"\n    s = str(name).strip()\n    if "\\\\" in s:\n        s = s.split("\\\\")[-1].strip()\n    if s.endswith("$"):\n        s = s[:-1].strip()\n    return s if s else "unknown-asset"\n\n\n# =========================================================\n# Fonts\n# =========================================================\ndef first_existing(paths: List[str]) -> Optional[str]:\n    for p in paths:\n        if p and os.path.exists(p):\n            return p\n    return None\n\ndef load_font(size: int, bold: bool = False) -> ImageFont.ImageFont:\n    if os.name == "nt":\n        regular = [r"C:\\Windows\\Fonts\\segoeui.ttf", r"C:\\Windows\\Fonts\\arial.ttf"]\n        bolds = [r"C:\\Windows\\Fonts\\segoeuib.ttf", r"C:\\Windows\\Fonts\\arialbd.ttf"]\n    else:\n        regular = [\n            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",\n            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",\n        ]\n        bolds = [\n            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",\n            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",\n        ]\n    path = first_existing(bolds if bold else regular) or first_existing(regular)\n    if path:\n        try:\n            return ImageFont.truetype(path, size=size)\n        except Exception:\n            pass\n    return ImageFont.load_default()\n\ndef text_width(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont) -> float:\n    try:\n        return draw.textlength(text, font=font)\n    except Exception:\n        return float(len(text) * 10)\n\ndef ellipsize(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont, max_w: int) -> str:\n    text = (text or "").strip()\n    if not text:\n        return ""\n    if text_width(draw, text, font) <= max_w:\n        return text\n    ell = "…"\n    lo, hi = 0, len(text)\n    while lo < hi:\n        mid = (lo + hi) // 2\n        candidate = text[:mid].rstrip() + ell\n        if text_width(draw, candidate, font) <= max_w:\n            lo = mid + 1\n        else:\n            hi = mid\n    candidate = text[:max(lo - 1, 0)].rstrip() + ell\n    if text_width(draw, candidate, font) > max_w:\n        return ell\n    return candidate\n\ndef wrap_lines(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont, max_w: int, max_lines: int) -> List[str]:\n    text = " ".join((text or "").split())\n    if not text:\n        return [""]\n    words = text.split(" ")\n    lines: List[str] = []\n    cur = ""\n    for w in words:\n        test = (cur + " " + w).strip()\n        if not cur or text_width(draw, test, font) <= max_w:\n            cur = test\n        else:\n            lines.append(cur)\n            cur = w\n            if len(lines) >= max_lines:\n                break\n    if len(lines) < max_lines and cur:\n        lines.append(cur)\n\n    if len(lines) > max_lines:\n        lines = lines[:max_lines]\n\n    # si truncamos, forzamos ellipsis en la última línea\n    joined = " ".join(lines)\n    if len(joined) < len(text):\n        lines[-1] = ellipsize(draw, lines[-1], font, max_w)\n\n    return lines\n\ndef rounded_rect(draw: ImageDraw.ImageDraw, box, radius: int, fill: str, outline: Optional[str] = None, width: int = 1):\n    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)\n\n\n# =========================================================\n# Tenable parsing (compliance export records)\n# =========================================================\ndef pick_result(rec: Dict[str, Any]) -> Optional[str]:\n    for k in ("status", "result", "compliance_result", "check_result", "state"):\n        v = rec.get(k)\n        if isinstance(v, str) and v.strip():\n            return v.strip().upper()\n    for parent in ("compliance", "check", "finding"):\n        v = rec.get(parent)\n        if isinstance(v, dict):\n            for k in ("status", "result", "compliance_result", "state"):\n                vv = v.get(k)\n                if isinstance(vv, str) and vv.strip():\n                    return vv.strip().upper()\n    return None\n\ndef normalize_result(r: Optional[str]) -> Optional[str]:\n    if not r:\n        return None\n    r = r.upper().strip()\n    if r in ("FAIL", "FAILED"):\n        return "FAILED"\n    if r in ("PASS", "PASSED", "SUCCESS"):\n        return "PASSED"\n    if r in ("WARN", "WARNING"):\n        return "WARNING"\n    if r in ("NOTAPPLICABLE", "NOT_APPLICABLE", "N/A", "NA"):\n        return None\n    if r in ("ERROR", "INFO"):\n        return "WARNING"\n    return None\n\ndef pick_asset_name(rec: Dict[str, Any]) -> str:\n    asset = rec.get("asset")\n    if isinstance(asset, dict):\n        for k in ("fqdn", "hostname", "netbios_name", "name", "display_name"):\n            v = asset.get(k)\n            if isinstance(v, str) and v.strip():\n                return normalize_asset_display_name(v)\n        for k in ("ipv4", "ip"):\n            v = asset.get(k)\n            if isinstance(v, str) and v.strip():\n                return v.strip()\n            if isinstance(v, list) and v:\n                return str(v[0])\n    for k in ("fqdn", "hostname", "netbios_name", "name", "ipv4", "ip"):\n        v = rec.get(k)\n        if isinstance(v, str) and v.strip():\n            return normalize_asset_display_name(v)\n    return "unknown-asset"\n\ndef extract_asset_tags(rec: Dict[str, Any]) -> List[Tuple[str, str]]:\n    tags: List[Tuple[str, str]] = []\n    asset = rec.get("asset")\n    if isinstance(asset, dict):\n        tlist = asset.get("tags")\n        if isinstance(tlist, list):\n            for t in tlist:\n                if not isinstance(t, dict):\n                    continue\n                cat = t.get("category") or t.get("category_name") or t.get("categoryName")\n                val = t.get("value") or t.get("value_name") or t.get("valueName")\n                if isinstance(cat, str) and isinstance(val, str) and cat.strip() and val.strip():\n                    tags.append((cat.strip(), val.strip()))\n    return tags\n\ndef pick_audit_name(rec: Dict[str, Any]) -> str:\n    for k in ("audit_name", "auditName", "check_name", "checkName", "control", "control_name", "item_name", "name"):\n        v = rec.get(k)\n        if isinstance(v, str) and v.strip():\n            return v.strip()\n    for parent in ("audit", "check", "compliance"):\n        v = rec.get(parent)\n        if isinstance(v, dict):\n            for k in ("name", "audit_name", "check_name", "title", "control"):\n                vv = v.get(k)\n                if isinstance(vv, str) and vv.strip():\n                    return vv.strip()\n    return "Unknown audit"\n\ndef pick_audit_file(rec: Dict[str, Any]) -> str:\n    for k in ("audit_file", "auditFile", "policy_name", "policy", "benchmark", "audit"):\n        v = rec.get(k)\n        if isinstance(v, str) and v.strip():\n            return v.strip()\n    for parent in ("audit", "policy", "compliance"):\n        v = rec.get(parent)\n        if isinstance(v, dict):\n            for k in ("file", "audit_file", "name", "policy_name", "benchmark"):\n                vv = v.get(k)\n                if isinstance(vv, str) and vv.strip():\n                    return vv.strip()\n    return "—"\n\ndef pick_plugin_name(rec: Dict[str, Any]) -> str:\n    for k in ("plugin_name", "pluginName", "plugin_family", "pluginFamily"):\n        v = rec.get(k)\n        if isinstance(v, str) and v.strip():\n            return v.strip()\n    plugin = rec.get("plugin")\n    if isinstance(plugin, dict):\n        for k in ("name", "family"):\n            v = plugin.get(k)\n            if isinstance(v, str) and v.strip():\n                return v.strip()\n    return "—"\n\ndef pick_solution(rec: Dict[str, Any]) -> Optional[str]:\n    candidates = []\n    for k in ("solution", "remediation", "recommendation", "fix", "fix_text", "policy_solution"):\n        v = rec.get(k)\n        if isinstance(v, str) and v.strip():\n            candidates.append(v.strip())\n    for parent in ("plugin", "audit", "check", "compliance", "finding"):\n        v = rec.get(parent)\n        if isinstance(v, dict):\n            for k in ("solution", "remediation", "recommendation", "fix"):\n                vv = v.get(k)\n                if isinstance(vv, str) and vv.strip():\n                    candidates.append(vv.strip())\n    if not candidates:\n        return None\n    return sorted(candidates, key=lambda x: len(x), reverse=True)[0]\n\n\n# =========================================================\n# Tags discovery (robusto)\n# =========================================================\ndef list_tag_categories(session: requests.Session) -> List[Dict[str, Any]]:\n    r = request_retry(session, "GET", "/tags/categories", headers=headers())\n    r.raise_for_status()\n    data = r.json()\n    return data.get("categories", []) if isinstance(data, dict) else []\n\ndef parse_tag_values_payload(data: Any) -> List[Tuple[str, str]]:\n    if not isinstance(data, dict):\n        return []\n    values = data.get("values")\n    if not isinstance(values, list):\n        return []\n    out: List[Tuple[str, str]] = []\n    for item in values:\n        if not isinstance(item, dict):\n            continue\n        cat = item.get("category_name") or item.get("category")\n        if isinstance(cat, dict):\n            cat = cat.get("name")\n        val = item.get("value") or item.get("value_name")\n        if isinstance(cat, str) and isinstance(val, str) and cat.strip() and val.strip():\n            out.append((cat.strip(), val.strip()))\n    return out\n\ndef list_tag_values_paged(session: requests.Session, *, filt: Optional[str] = None, limit: int = 1000) -> List[Tuple[str, str]]:\n    out: List[Tuple[str, str]] = []\n    offset = 0\n    while True:\n        params = {"limit": limit, "offset": offset}\n        if filt:\n            params["f"] = filt\n        r = request_retry(session, "GET", "/tags/values", headers=headers(), params=params)\n        r.raise_for_status()\n        data = r.json()\n        batch = parse_tag_values_payload(data)\n        out.extend(batch)\n        if len(batch) < limit:\n            break\n        offset += limit\n    return sorted(set(out), key=lambda x: (_norm(x[0]), _norm(x[1])))\n\ndef discover_all_tags(session: requests.Session) -> List[Tuple[str, str]]:\n    tags = list_tag_values_paged(session)\n    if tags:\n        return tags\n    cats = list_tag_categories(session)\n    tags2: List[Tuple[str, str]] = []\n    for c in cats:\n        cuuid = c.get("uuid")\n        if isinstance(cuuid, str) and cuuid.strip():\n            tags2.extend(list_tag_values_paged(session, filt=f"category_uuid:eq:{cuuid.strip()}"))\n    return sorted(set(tags2), key=lambda x: (_norm(x[0]), _norm(x[1])))\n\n\n# =========================================================\n# Compliance export (global)\n# =========================================================\ndef create_compliance_export_all(session: requests.Session) -> str:\n    payload_variants = [\n        {"num_findings": NUM_FINDINGS_PER_CHUNK},\n        {"num_findings": NUM_FINDINGS_PER_CHUNK, "filters": {}},\n        {"filters": {}},\n        {},\n    ]\n    last_text = None\n    for body in payload_variants:\n        r = request_retry(session, "POST", "/compliance/export", headers=headers(), json=body)\n        if r.status_code == 200:\n            resp = r.json()\n            export_uuid = resp.get("export_uuid") or resp.get("uuid") or resp.get("id")\n            if export_uuid:\n                return export_uuid\n            raise RuntimeError(f"No encontré export_uuid en respuesta: {resp}")\n        last_text = f"[{r.status_code}] {r.text}"\n    raise RuntimeError(f"No se pudo crear export global. Último error: {last_text}")\n\ndef poll_chunks(session: requests.Session, export_uuid: str) -> List[int]:\n    start = time.time()\n    chunk_ids: List[int] = []\n    while True:\n        r = request_retry(session, "GET", f"/compliance/export/{export_uuid}/status", headers=headers())\n        r.raise_for_status()\n        st = r.json()\n        status = (st.get("status") or "").upper()\n\n        ca = st.get("chunks_available")\n        if isinstance(ca, list):\n            for x in ca:\n                try:\n                    chunk_ids.append(int(x))\n                except Exception:\n                    pass\n\n        ch = st.get("chunks")\n        if isinstance(ch, list):\n            for x in ch:\n                if isinstance(x, int):\n                    chunk_ids.append(x)\n                elif isinstance(x, dict):\n                    cid = x.get("id") or x.get("chunk_id")\n                    if isinstance(cid, int):\n                        chunk_ids.append(cid)\n                    elif isinstance(cid, str) and cid.isdigit():\n                        chunk_ids.append(int(cid))\n\n        chunk_ids = sorted(set(chunk_ids))\n        if status in ("FINISHED", "CANCELLED", "ERROR") and chunk_ids:\n            return chunk_ids\n\n        if time.time() - start > POLL_TIMEOUT_SEC:\n            if chunk_ids:\n                return chunk_ids\n            raise TimeoutError(f"Timeout esperando chunks. Último status: {st}")\n\n        time.sleep(POLL_INTERVAL_SEC)\n\ndef download_chunk(session: requests.Session, export_uuid: str, chunk_id: int) -> List[Dict[str, Any]]:\n    r = request_retry(session, "GET", f"/compliance/export/{export_uuid}/chunks/{chunk_id}", headers=headers())\n    r.raise_for_status()\n    try:\n        payload = r.json()\n    except Exception:\n        payload = try_parse_payload(r.content)\n    return extract_records(payload)\n\ndef iter_records_from_api(session: requests.Session):\n    export_uuid = create_compliance_export_all(session)\n    print(f"✅ Export global creado: {export_uuid}")\n    chunk_ids = poll_chunks(session, export_uuid)\n    print(f"✅ Chunks a descargar: {len(chunk_ids)}")\n    for cid in chunk_ids:\n        recs = download_chunk(session, export_uuid, cid)\n        for r in recs:\n            yield r\n\n\n# =========================================================\n# Aggregation\n# =========================================================\ndef aggregate(records_iter, allowed_tags: set[Tuple[str, str]]):\n    out: Dict[Tuple[str, str], Dict[Tuple[str, str, str], Dict[str, Any]]] = defaultdict(dict)\n\n    processed = 0\n    matched = 0\n\n    for rec in records_iter:\n        processed += 1\n\n        res = normalize_result(pick_result(rec))\n        if not res or res not in ONLY_RESULT:\n            continue\n\n        tags = extract_asset_tags(rec)\n        if not tags:\n            continue\n\n        audit_name = pick_audit_name(rec)\n        audit_file = pick_audit_file(rec)\n        plugin_name = pick_plugin_name(rec)\n        solution = pick_solution(rec)\n        asset = pick_asset_name(rec)\n\n        audit_key = (audit_name, audit_file, plugin_name)\n\n        for (cat, val) in tags:\n            tag = (cat, val)\n            if tag not in allowed_tags:\n                continue\n\n            slot = out[tag].get(audit_key)\n            if slot is None:\n                slot = {\n                    "audit_name": audit_name,\n                    "audit_file": audit_file,\n                    "plugin_name": plugin_name,\n                    "failed_count": 0,\n                    "assets_sample": [],\n                    "_assets_set": set(),\n                    "solution": None,\n                }\n                out[tag][audit_key] = slot\n\n            slot["failed_count"] += 1\n\n            aset = slot["_assets_set"]\n            if asset not in aset and len(aset) < 4000:\n                aset.add(asset)\n                if len(slot["assets_sample"]) < 25:\n                    slot["assets_sample"].append(asset)\n\n            if solution and (slot["solution"] is None or len(solution) > len(slot["solution"])):\n                slot["solution"] = solution\n\n            matched += 1\n\n        if processed % 25000 == 0:\n            print(f"  ...procesados {processed:,} records | matched(tag-assign) {matched:,}")\n\n    for tag, audits in out.items():\n        for _, slot in audits.items():\n            slot.pop("_assets_set", None)\n\n    return out\n\n\n# =========================================================\n# Rendering (PIL) - improved, no overlap\n# =========================================================\ndef draw_list_image(tag_label: str, rows: List[Dict[str, Any]], out_png: str,\n                    rows_to_show: int, assets_per_row: int):\n    img = Image.new("RGB", (IMG_W, IMG_H), COL_BG)\n    d = ImageDraw.Draw(img)\n\n    f_title = load_font(68, True)\n    f_sub = load_font(34, False)\n    f_hdr = load_font(34, True)\n    f_cell = load_font(30, False)\n    f_cell_b = load_font(30, True)\n\n    pad = 140\n    top = 90\n\n    d.text((pad, top), "Host Audits", font=f_title, fill=TEXT)\n    d.text((pad, top + 80), "Failed checks (sample)", font=f_sub, fill=MUTED)\n    d.text((pad, top + 130), tag_label, font=f_sub, fill=MUTED2)\n\n    card_x1 = pad\n    card_y1 = top + 210\n    card_x2 = IMG_W - pad\n    card_y2 = IMG_H - 140\n\n    rounded_rect(d, (card_x1, card_y1, card_x2, card_y2), 26, CARD_BG, BORDER, 3)\n\n    inner_pad = 40\n    x1 = card_x1 + inner_pad\n    y1 = card_y1 + inner_pad\n    x2 = card_x2 - inner_pad\n    y2 = card_y2 - inner_pad\n\n    col_names = ["Audit Name", "Audit File", "Result", "Plugin Name", "Assets (sample)"]\n    col_fracs = [0.40, 0.22, 0.10, 0.16, 0.12]\n    usable_w = x2 - x1\n    col_w = [int(usable_w * f) for f in col_fracs]\n    col_w[-1] = usable_w - sum(col_w[:-1])\n\n    header_h = 72\n    table_h = y2 - y1\n    available_for_rows = table_h - header_h - 20\n\n    # auto-ajuste para que NO se encime\n    max_rows_fit = max(1, available_for_rows // 110)\n    show_n = min(rows_to_show, max_rows_fit, len(rows))\n    row_h = max(96, available_for_rows // max(1, show_n))\n\n    rounded_rect(d, (x1, y1, x2, y1 + header_h), 18, HEADER_BG, BORDER, 2)\n\n    cx = x1\n    for w in col_w[:-1]:\n        cx += w\n        d.line((cx, y1, cx, y2), fill=BORDER, width=2)\n\n    cx = x1 + 18\n    for name, w in zip(col_names, col_w):\n        d.text((cx, y1 + 18), name, font=f_hdr, fill=TEXT)\n        cx += w\n\n    if not rows:\n        d.text((x1 + 30, y1 + header_h + 60), "No data for this tag", font=f_sub, fill=MUTED2)\n        os.makedirs(os.path.dirname(out_png) or ".", exist_ok=True)\n        img.save(out_png, "PNG", optimize=True)\n        return\n\n    start_y = y1 + header_h + 10\n\n    for i in range(show_n):\n        r = rows[i]\n        ry1 = start_y + i * row_h\n        ry2 = ry1 + row_h\n\n        bg = CARD_BG if i % 2 == 0 else ROW_ALT\n        d.rectangle((x1, ry1, x2, ry2), fill=bg)\n        d.line((x1, ry2, x2, ry2), fill=BORDER, width=2)\n\n        cx = x1 + 18\n        pad_y = 14\n\n        # Audit name (2 lines)\n        max_w = col_w[0] - 36\n        lines = wrap_lines(d, r.get("audit_name", ""), f_cell, max_w, 2)\n        d.text((cx, ry1 + pad_y), lines[0], font=f_cell, fill=TEXT)\n        if len(lines) > 1:\n            d.text((cx, ry1 + pad_y + 38), lines[1], font=f_cell, fill=TEXT)\n        cx += col_w[0]\n\n        # Audit file (2 lines)\n        max_w = col_w[1] - 36\n        lines = wrap_lines(d, r.get("audit_file", ""), f_cell, max_w, 2)\n        d.text((cx, ry1 + pad_y), lines[0], font=f_cell, fill=MUTED)\n        if len(lines) > 1:\n            d.text((cx, ry1 + pad_y + 38), lines[1], font=f_cell, fill=MUTED)\n        cx += col_w[1]\n\n        # Result (icon + text)\n        icon_cx = cx + 22\n        icon_cy = ry1 + row_h // 2\n        d.ellipse((icon_cx - 12, icon_cy - 12, icon_cx + 12, icon_cy + 12), outline=FAIL_RED, width=4)\n        d.line((icon_cx - 8, icon_cy + 8, icon_cx + 8, icon_cy - 8), fill=FAIL_RED, width=4)\n        d.text((cx + 50, icon_cy - 16), "Failed", font=f_cell_b, fill=FAIL_RED)\n        cx += col_w[2]\n\n        # Plugin name (max 2 lines)\n        max_w = col_w[3] - 36\n        lines = wrap_lines(d, r.get("plugin_name", ""), f_cell, max_w, 2)\n        d.text((cx, ry1 + pad_y), lines[0], font=f_cell, fill=TEXT)\n        if len(lines) > 1:\n            d.text((cx, ry1 + pad_y + 38), lines[1], font=f_cell, fill=TEXT)\n        cx += col_w[3]\n\n        # Assets sample (n lines, cada asset en su línea)\n        assets = (r.get("assets_sample", []) or [])[:assets_per_row]\n        max_w = col_w[4] - 36\n        for li, a in enumerate(assets[:3]):\n            d.text((cx, ry1 + pad_y + li * 36), ellipsize(d, a, f_cell, max_w), font=f_cell, fill=TEXT)\n        if not assets:\n            d.text((cx, ry1 + pad_y), "—", font=f_cell, fill=MUTED2)\n\n    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")\n    d.text((card_x1 + 40, card_y2 - 55), f"Generated: {now}", font=load_font(26, False), fill=MUTED2)\n\n    os.makedirs(os.path.dirname(out_png) or ".", exist_ok=True)\n    img.save(out_png, "PNG", optimize=True)\n\n\ndef draw_detail_image(tag_label: str, detail: Dict[str, Any], out_png: str):\n    img = Image.new("RGB", (IMG_W, IMG_H), COL_BG)\n    d = ImageDraw.Draw(img)\n\n    f_title = load_font(64, True)\n    f_h2 = load_font(42, True)\n    f_lbl = load_font(30, True)\n    f_txt = load_font(30, False)\n    f_small = load_font(26, False)\n\n    pad = 140\n    card_x1 = pad\n    card_y1 = 120\n    card_x2 = IMG_W - pad\n    card_y2 = IMG_H - 140\n\n    rounded_rect(d, (card_x1, card_y1, card_x2, card_y2), 30, CARD_BG, BORDER, 3)\n\n    x = card_x1 + 80\n    y = card_y1 + 70\n    max_w = (card_x2 - card_x1) - 160\n\n    title_lines = wrap_lines(d, detail.get("audit_name", "Audit detail"), f_title, max_w, 2)\n    d.text((x, y), title_lines[0], font=f_title, fill=TEXT)\n    if len(title_lines) > 1:\n        d.text((x, y + 72), title_lines[1], font=f_title, fill=TEXT)\n        y += 72\n    y += 88\n\n    audit_file = detail.get("audit_file", "—")\n    plugin = detail.get("plugin_name", "—")\n    d.text((x, y), f"Audit File: {audit_file}", font=f_txt, fill=MUTED)\n    y += 40\n    d.text((x, y), f"Plugin: {plugin}", font=f_txt, fill=MUTED)\n    y += 70\n\n    # pill + contador (reacomodado para nunca encimar)\n    pill_h = 62\n    pill_w = 320\n    rounded_rect(d, (x, y, x + pill_w, y + pill_h), 22, FAIL_RED, None, 0)\n    d.text((x + 110, y + 14), "FAILED", font=f_lbl, fill="white")\n\n    failed = int(detail.get("failed_count", 0) or 0)\n    d.text((x + pill_w + 30, y + 14), f"Failed instances: {failed}", font=f_lbl, fill=TEXT)\n    y += pill_h + 55\n\n    d.line((x, y, card_x2 - 80, y), fill=BORDER, width=3)\n    y += 45\n\n    d.text((x, y), "Assets (sample)", font=f_h2, fill=TEXT)\n    y += 60\n\n    assets = (detail.get("assets_sample", []) or [])[:12]\n    for a in assets:\n        d.text((x, y), f"• {a}", font=f_txt, fill=TEXT)\n        y += 40\n\n    y += 10\n    d.text((x, y), "Fixes", font=f_h2, fill=TEXT)\n    y += 60\n    d.text((x, y), "Solution", font=f_lbl, fill=TEXT)\n    y += 48\n\n    sol = (detail.get("solution") or "").strip() or "—"\n    sol = re.sub(r"\\s+\\n", "\\n", sol)\n    sol = re.sub(r"\\n{3,}", "\\n\\n", sol)\n    sol = sol.replace("\\t", " ")\n\n    sol_box_x1 = x\n    sol_box_y1 = y\n    sol_box_x2 = card_x2 - 80\n    sol_box_y2 = card_y2 - 95\n\n    max_w = sol_box_x2 - sol_box_x1\n    max_h = sol_box_y2 - sol_box_y1\n    max_lines = max(1, max_h // 38)\n\n    paragraphs = [p.strip() for p in sol.splitlines() if p.strip()]\n    lines: List[str] = []\n    for p in paragraphs:\n        lines.extend(wrap_lines(d, p, f_txt, max_w, 2000))\n        lines.append("")\n    if lines and lines[-1] == "":\n        lines.pop()\n\n    if len(lines) > max_lines:\n        lines = lines[:max_lines]\n        lines[-1] = ellipsize(d, lines[-1], f_txt, max_w)\n\n    for i, line in enumerate(lines):\n        d.text((sol_box_x1, sol_box_y1 + i * 38), line, font=f_txt, fill=MUTED)\n\n    gen = detail.get("generated_at") or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")\n    footer = f"{tag_label}  •  Generated: {gen}"\n    d.text((card_x1 + 80, card_y2 - 55), footer, font=f_small, fill=MUTED2)\n\n    os.makedirs(os.path.dirname(out_png) or ".", exist_ok=True)\n    img.save(out_png, "PNG", optimize=True)\n\n\n# =========================================================\n# Main\n# =========================================================\ndef main():\n    ap = argparse.ArgumentParser()\n    ap.add_argument("--only-category", action="append", default=[], help="Procesa SOLO esta categoría (puedes repetir)")\n    ap.add_argument("--max-tags", type=int, default=0, help="0=sin límite. Para pruebas, limita tags procesadas.")\n    ap.add_argument("--rows", type=int, default=12, help="Filas en tabla (auto-ajusta si no caben)")\n    ap.add_argument("--assets-per-row", type=int, default=3, help="Assets mostrados por fila")\n    ap.add_argument("--out-dir", default=os.path.join("tenable_cis_host_audits_by_tag", datetime.now(timezone.utc).strftime("%Y-%m")), help="Directorio de salida")\n    args = ap.parse_args()\n\n    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:\n        raise SystemExit("❌ Define TENABLE_ACCESS_KEY y TENABLE_SECRET_KEY (variables de entorno).")\n\n    session = requests.Session()\n\n    print("▶ Descubriendo tags con /tags/values ...")\n    tags = discover_all_tags(session)\n    if not tags:\n        raise SystemExit("❌ No pude descubrir tags en tu tenant. Revisa permisos y que existan tags.")\n\n    if args.only_category:\n        wanted = {_norm(x) for x in args.only_category}\n        tags = [t for t in tags if _norm(t[0]) in wanted]\n\n    if args.max_tags and args.max_tags > 0:\n        tags = tags[:args.max_tags]\n\n    print(f"✅ Tags a procesar: {len(tags)}")\n    allowed = set(tags)\n\n    print("▶ Descargando y agregando Compliance export (FAILED) ...")\n    aggregated = aggregate(iter_records_from_api(session), allowed)\n\n    os.makedirs(args.out_dir, exist_ok=True)\n    index: List[Dict[str, Any]] = []\n    gen_ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")\n\n    print(f"▶ Generando imágenes en: {args.out_dir}")\n\n    for i, (cat, val) in enumerate(tags, start=1):\n        tag_label = f"{cat} = {val}"\n        out_dir = os.path.join(args.out_dir, safe_fs_name(cat), safe_fs_name(val))\n        os.makedirs(out_dir, exist_ok=True)\n\n        audits = aggregated.get((cat, val), {})\n        rows: List[Dict[str, Any]] = list(audits.values())\n        rows.sort(key=lambda x: int(x.get("failed_count", 0)), reverse=True)\n\n        list_png = os.path.join(out_dir, "01_audits_list_4k.png")\n        detail_png = os.path.join(out_dir, "02_audit_detail_4k.png")\n\n        draw_list_image(tag_label, rows, list_png, rows_to_show=args.rows, assets_per_row=args.assets_per_row)\n\n        if rows:\n            top = dict(rows[0])\n            top["generated_at"] = gen_ts\n            draw_detail_image(tag_label, top, detail_png)\n            status = "OK"\n        else:\n            draw_detail_image(tag_label, {\n                "audit_name": "No audits for this tag",\n                "audit_file": "—",\n                "plugin_name": "—",\n                "failed_count": 0,\n                "assets_sample": [],\n                "solution": "—",\n                "generated_at": gen_ts\n            }, detail_png)\n            status = "NO DATA"\n\n        index.append({\n            "tag": {"category": cat, "value": val},\n            "status": status,\n            "paths": {"list": list_png, "detail": detail_png},\n        })\n\n        print(f"[{i}/{len(tags)}] ✅ {tag_label} -> {status}")\n\n    with open(os.path.join(args.out_dir, "index.json"), "w", encoding="utf-8") as f:\n        json.dump(index, f, ensure_ascii=False, indent=2)\n\n    print("\\n✅ Listo.")\n\nif __name__ == "__main__":\n    main()\n',
    "tenable_images": '# -*- coding: utf-8 -*-\n"""\nTenable VM (cloud.tenable.com) -> IMÁGENES (sin JSON)\n\nGenera por cada tag:\n  1) Barras por severidad (colores tipo Tenable + número arriba)\n  2) Top 10 por VPR como lista (SIN columna Instances)\n  3) "Spotlight" (tipo Tenable Finding) de la vulnerabilidad MÁS CRÍTICA dentro del Top 10\n\nNotas importantes:\n- VPR suele ser del plugin/finding (no del asset).\n- ACR es del ASSET (host) afectado. Para el spotlight usamos el ACR del asset representativo del finding.\n  Si el export no trae ACR, se intenta enriquecer con GET /assets/{asset_uuid}.\n\nRequisitos:\n  pip install requests matplotlib\n\nEjecución:\n  python tags_images_v6.py\n\n⚠️ Permite hardcodear keys para PRUEBAS. NO subas esto a Git.\n"""\n\nimport os\nimport re\nimport json\nimport time\nimport gzip\nimport unicodedata\nimport textwrap\nfrom datetime import datetime, timezone\nfrom collections import defaultdict\nfrom typing import Dict, Any, List, Optional, Tuple\n\nimport requests\n\nimport matplotlib\nmatplotlib.use("Agg")\nimport matplotlib.pyplot as plt\nfrom matplotlib.patches import Rectangle, FancyBboxPatch\n\n\n# =========================\n# 🔐 API KEYS (HARDCODED para pruebas)\n# =========================\nBASE = TENABLE_BASE_URL\n\nWANTED_CATEGORIES = ["UN", "Razón Social", "Omnilife"]\nINCLUDE_UNLICENSED = True\nFORCE_NO_30D_LIMIT = True\nSLEEP_BETWEEN_EXPORTS_SECONDS = 0\n\nOUTPUT_ROOT = os.path.join("tenable_outputs", datetime.now(timezone.utc).strftime("%Y-%m"))\n\nIMG_DPI = 160\nSEV_IMG_SIZE = (12.6, 4.2)\nTOP10_IMG_SIZE = (14.0, 7.6)\nSPOT_IMG_SIZE = (12.8, 6.9)\n\nSEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]\nSEVERITY_COLORS = {\n    "critical": "#D14343",\n    "high":     "#F08A24",\n    "medium":   "#F2C94C",\n    "low":      "#4A90E2",\n    "info":     "#9CA3AF",\n    "none":     "#CBD5E1",\n}\nSEVERITY_LABELS = {\n    "critical": "Critical",\n    "high": "High",\n    "medium": "Medium",\n    "low": "Low",\n    "info": "Info",\n    "none": "None",\n}\nSEV_INT_MAP = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}\n\n\n# -------------------------\n# Utils\n# -------------------------\ndef norm(s: str) -> str:\n    s = (s or "").strip().lower()\n    s = "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn")\n    s = re.sub(r"\\s+", " ", s)\n    return s\n\ndef slug(s: str, max_len: int = 70) -> str:\n    s = norm(s)\n    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_").upper() or "NA"\n    return s[:max_len]\n\ndef ensure_dir(path: str) -> None:\n    os.makedirs(path, exist_ok=True)\n\ndef now_utc_iso() -> str:\n    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")\n\ndef truncate(s: str, max_chars: int) -> str:\n    s = (s or "").strip()\n    if len(s) <= max_chars:\n        return s\n    return s[: max(0, max_chars - 1)].rstrip() + "…"\n\ndef wrap_lines(s: Optional[str], width: int, max_lines: int) -> str:\n    if not s:\n        return "—"\n    s = " ".join(str(s).split())\n    lines = textwrap.wrap(s, width=width)\n    if len(lines) > max_lines:\n        lines = lines[:max_lines]\n        lines[-1] = lines[-1].rstrip(".") + "…"\n    return "\\n".join(lines)\n\ndef sev_rank(sev: str) -> int:\n    return {"none": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, -1)\n\ndef sev_from_rank(rank: int) -> str:\n    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}.get(rank, "none")\n\n\n# -------------------------\n# HTTP wrapper\n# -------------------------\ndef make_session() -> requests.Session:\n    ak = TENABLE_ACCESS_KEY\n    sk = TENABLE_SECRET_KEY\n\n    if "PASTE_" in ak or "PASTE_" in sk:\n        ak = os.getenv("TENABLE_ACCESS_KEY", ak)\n        sk = os.getenv("TENABLE_SECRET_KEY", sk)\n\n    if not ak or not sk or "PASTE_" in ak or "PASTE_" in sk:\n        raise SystemExit("❌ Pega tus llaves en TENABLE_ACCESS_KEY/TENABLE_SECRET_KEY o define variables de entorno.")\n\n    s = requests.Session()\n    s.headers.update({\n        "X-ApiKeys": f"accessKey={ak}; secretKey={sk}",\n        "Accept": "application/json",\n        "Content-Type": "application/json",\n    })\n    return s\n\ndef request_json(sess: requests.Session, method: str, path: str, *, params=None, json_body=None, stream=False, max_retries=8):\n    url = BASE + path\n    for attempt in range(max_retries):\n        r = sess.request(method, url, params=params, json=json_body, timeout=300, stream=stream)\n\n        if r.status_code == 429:\n            ra = r.headers.get("Retry-After")\n            sleep_s = int(ra) if ra and ra.isdigit() else min(2 ** attempt, 30)\n            time.sleep(sleep_s)\n            continue\n\n        if r.status_code in (500, 502, 503, 504):\n            time.sleep(min(2 ** attempt, 30))\n            continue\n\n        r.raise_for_status()\n        if stream:\n            return r.content\n        return r.json()\n\n    raise RuntimeError(f"Request failed after retries: {method} {path}")\n\n\n# -------------------------\n# Tags\n# -------------------------\ndef list_tag_categories(sess: requests.Session) -> List[Dict[str, Any]]:\n    data = request_json(sess, "GET", "/tags/categories")\n    return data.get("categories", [])\n\ndef list_tag_values_by_category_uuid(sess: requests.Session, category_uuid: str, limit: int = 1000) -> List[Dict[str, Any]]:\n    out: List[Dict[str, Any]] = []\n    offset = 0\n    while True:\n        params = {"limit": limit, "offset": offset, "f": f"category_uuid:eq:{category_uuid}"}\n        data = request_json(sess, "GET", "/tags/values", params=params)\n        values = data.get("values", [])\n        out.extend(values)\n        if len(values) < limit:\n            break\n        offset += limit\n    return out\n\ndef discover_targets(sess: requests.Session) -> List[Dict[str, str]]:\n    wanted = {norm(x) for x in WANTED_CATEGORIES}\n\n    categories = list_tag_categories(sess)\n    selected = []\n    for c in categories:\n        name = c.get("name", "")\n        if norm(name) in wanted and c.get("uuid"):\n            selected.append({"name": name, "uuid": c["uuid"]})\n\n    if not selected:\n        raise SystemExit("❌ No encontré categorías UN / Razón Social / Omnilife. Revisa el nombre exacto en Tenable.")\n\n    targets: List[Dict[str, str]] = []\n    for cat in selected:\n        vals = list_tag_values_by_category_uuid(sess, cat["uuid"])\n        for v in vals:\n            value = v.get("value")\n            vuuid = v.get("uuid")\n            if not value or not vuuid:\n                continue\n            targets.append({\n                "id": f"{slug(cat[\'name\'])}_{slug(value)}",\n                "tag_category": cat["name"],\n                "tag_value": value,\n                "tag_value_uuid": vuuid\n            })\n\n    targets.sort(key=lambda t: (norm(t["tag_category"]), norm(t["tag_value"])))\n    return targets\n\n\n# -------------------------\n# Vulns Export helpers\n# -------------------------\ndef create_vulns_export(sess: requests.Session, filters: Dict[str, Any], num_assets: int = 5000) -> str:\n    body = {"filters": filters, "num_assets": num_assets, "include_unlicensed": INCLUDE_UNLICENSED}\n    data = request_json(sess, "POST", "/vulns/export", json_body=body)\n    export_uuid = data.get("export_uuid")\n    if not export_uuid:\n        raise RuntimeError(f"No export_uuid: {data}")\n    return export_uuid\n\ndef export_status(sess: requests.Session, export_uuid: str) -> Dict[str, Any]:\n    return request_json(sess, "GET", f"/vulns/export/{export_uuid}/status")\n\ndef download_chunk_raw(sess: requests.Session, export_uuid: str, chunk_id: int) -> bytes:\n    return request_json(sess, "GET", f"/vulns/export/{export_uuid}/chunks/{chunk_id}", stream=True)\n\ndef iter_records_from_chunk(raw: bytes):\n    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:\n        raw = gzip.decompress(raw)\n\n    try:\n        data = json.loads(raw.decode("utf-8"))\n        if isinstance(data, list):\n            for rec in data:\n                yield rec\n            return\n        if isinstance(data, dict):\n            yield data\n            return\n    except Exception:\n        pass\n\n    for line in raw.splitlines():\n        line = line.strip()\n        if not line:\n            continue\n        yield json.loads(line.decode("utf-8"))\n\n\n# -------------------------\n# Parsing helpers\n# -------------------------\ndef normalize_severity(row: Dict[str, Any]) -> str:\n    sev = row.get("severity")\n    if isinstance(sev, dict):\n        sev = sev.get("name") or sev.get("value")\n\n    if isinstance(sev, int):\n        return SEV_INT_MAP.get(sev, "none")\n\n    if sev is None:\n        return "none"\n\n    s = str(sev).strip().lower()\n    mapping = {\n        "informational": "info",\n        "information": "info",\n        "none": "none",\n        "unknown": "none",\n        "info": "info",\n        "low": "low",\n        "medium": "medium",\n        "high": "high",\n        "critical": "critical",\n    }\n    return mapping.get(s, "none")\n\ndef get_asset(row: Dict[str, Any]) -> Dict[str, Any]:\n    a = row.get("asset")\n    return a if isinstance(a, dict) else {}\n\ndef get_asset_uuid(row: Dict[str, Any]) -> Optional[str]:\n    a = get_asset(row)\n    v = a.get("uuid")\n    return v if isinstance(v, str) and v.strip() else None\n\n\ndef get_asset_id(row: Dict[str, Any]) -> Optional[str]:\n    a = get_asset(row)\n    v = a.get("id") or row.get("asset_id")\n    if v is None:\n        return None\n    # puede ser int\n    try:\n        return str(int(v))\n    except Exception:\n        return str(v)\n\ndef get_asset_label(row: Dict[str, Any]) -> str:\n    a = get_asset(row)\n    for k in ("hostname", "fqdn", "netbios_name", "display_name", "name"):\n        v = a.get(k)\n        if isinstance(v, str) and v.strip():\n            return v.strip()\n    for k in ("ipv4", "display_ipv4_address", "ip"):\n        v = a.get(k)\n        if isinstance(v, str) and v.strip():\n            return v.strip()\n    return "—"\n\ndef get_asset_acr_from_row(row: Dict[str, Any]) -> Optional[float]:\n    a = get_asset(row)\n    for k in ("acr_score", "acr", "asset_criticality_rating"):\n        v = a.get(k)\n        if v is None:\n            continue\n        if isinstance(v, dict):\n            v = v.get("score") or v.get("value")\n        try:\n            return float(v)\n        except Exception:\n            continue\n    # a veces viene en risk_information del finding/asset\n    plugin = row.get("plugin") or {}\n    ri = plugin.get("risk_information") or row.get("risk_information") or {}\n    if isinstance(ri, dict):\n        for k in ("acr_score", "acr"):\n            v = ri.get(k)\n            if v is None:\n                continue\n            if isinstance(v, dict):\n                v = v.get("score")\n            try:\n                return float(v)\n            except Exception:\n                continue\n    return None\n\ndef get_plugin_id(row: Dict[str, Any]) -> Optional[int]:\n    plugin = row.get("plugin") or {}\n    pid = plugin.get("id") or row.get("plugin_id")\n    try:\n        return int(pid) if pid is not None else None\n    except Exception:\n        return None\n\ndef get_plugin_name(row: Dict[str, Any]) -> str:\n    plugin = row.get("plugin") or {}\n    return plugin.get("name") or row.get("plugin_name") or "Unknown plugin"\n\ndef get_vpr_and_beta(row: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:\n    """\n    VPR puede venir en varias ubicaciones.\n    """\n    plugin = row.get("plugin") or {}\n    ri = plugin.get("risk_information") or row.get("risk_information") or {}\n\n    vpr = None\n    vpr_beta = None\n\n    # VPR Beta (v2)\n    candidates_beta = [\n        plugin.get("vpr_v2"),\n        ri.get("vpr_v2") if isinstance(ri, dict) else None,\n        row.get("vpr_v2"),\n        row.get("vpr_beta"),\n    ]\n    for c in candidates_beta:\n        if c is None:\n            continue\n        if isinstance(c, dict):\n            c = c.get("score") or c.get("value")\n        try:\n            vpr_beta = float(c)\n            break\n        except Exception:\n            continue\n\n    # VPR normal\n    candidates = [\n        plugin.get("vpr"),\n        plugin.get("vpr_score"),\n        ri.get("vpr") if isinstance(ri, dict) else None,\n        ri.get("vpr_score") if isinstance(ri, dict) else None,\n        row.get("vpr"),\n        row.get("vpr_score"),\n    ]\n    for c in candidates:\n        if c is None:\n            continue\n        if isinstance(c, dict):\n            c = c.get("score") or c.get("value")\n        try:\n            vpr = float(c)\n            break\n        except Exception:\n            continue\n\n    return vpr, vpr_beta\n\ndef get_cvss3(row: Dict[str, Any]) -> Optional[float]:\n    plugin = row.get("plugin") or {}\n    candidates = [\n        plugin.get("cvss3_base_score"),\n        plugin.get("cvss3_score"),\n        plugin.get("cvss3"),\n        row.get("cvss3_base_score"),\n        row.get("cvss3_score"),\n    ]\n    for c in candidates:\n        if c is None:\n            continue\n        if isinstance(c, dict):\n            c = c.get("base_score") or c.get("score")\n        try:\n            return float(c)\n        except Exception:\n            continue\n    return None\n\ndef get_key_drivers(row: Dict[str, Any]) -> List[str]:\n    plugin = row.get("plugin") or {}\n    ri = plugin.get("risk_information") or row.get("risk_information") or {}\n    kd = plugin.get("key_drivers") or row.get("key_drivers")\n    if kd is None and isinstance(ri, dict):\n        kd = ri.get("key_drivers") or ri.get("drivers")\n\n    out: List[str] = []\n    if isinstance(kd, list):\n        for x in kd:\n            if not x:\n                continue\n            if isinstance(x, dict):\n                x = x.get("name") or x.get("driver") or x.get("value") or str(x)\n            out.append(str(x).strip())\n    elif isinstance(kd, str) and kd.strip():\n        out = [kd.strip()]\n\n    return [x for x in out if x]\n\ndef get_solution_workaround(row: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:\n    plugin = row.get("plugin") or {}\n    sol = plugin.get("solution") or row.get("solution")\n    wor = plugin.get("workaround") or row.get("workaround")\n    return sol, wor\n\ndef get_finding_id(row: Dict[str, Any]) -> Optional[str]:\n    for k in ("id", "finding_id", "vuln_id", "uuid"):\n        v = row.get(k)\n        if isinstance(v, str) and v.strip():\n            return v.strip()\n    return None\n\n\n# -------------------------\n# Enrichment: plugin + asset\n# -------------------------\ndef fetch_plugin_details(sess: requests.Session, plugin_id: int) -> Dict[str, Any]:\n    try:\n        return request_json(sess, "GET", f"/plugins/plugin/{plugin_id}")\n    except Exception:\n        return {}\n\ndef fetch_asset_details(sess: requests.Session, asset_uuid: Optional[str], asset_id: Optional[str] = None) -> Dict[str, Any]:\n    """Tenable expone /assets/{id} (en muchos tenants el \'id\' es numérico).\n    En algunos exports tenemos asset.uuid y/o asset.id. Probamos ambos.\n    """\n    for identifier in [asset_uuid, asset_id]:\n        if not identifier:\n            continue\n        try:\n            return request_json(sess, "GET", f"/assets/{identifier}")\n        except Exception:\n            continue\n    return {}\n    try:\n        return request_json(sess, "GET", f"/assets/{asset_uuid}")\n    except Exception:\n        return {}\n\ndef enrich_from_plugin_details(current: Dict[str, Any], plugin_details: Dict[str, Any]) -> Dict[str, Any]:\n    out = dict(current)\n    if not isinstance(plugin_details, dict):\n        return out\n\n    info = plugin_details.get("info") if isinstance(plugin_details.get("info"), dict) else {}\n    ri = plugin_details.get("risk_information") if isinstance(plugin_details.get("risk_information"), dict) else {}\n\n    out["name"] = out.get("name") or info.get("name") or plugin_details.get("name")\n    out["solution"] = out.get("solution") or info.get("solution") or plugin_details.get("solution")\n    out["workaround"] = out.get("workaround") or info.get("workaround") or plugin_details.get("workaround")\n\n    if out.get("cvss3") is None:\n        for c in (info.get("cvss3_base_score"), plugin_details.get("cvss3_base_score"), ri.get("cvss3_base_score")):\n            if c is None:\n                continue\n            try:\n                out["cvss3"] = float(c)\n                break\n            except Exception:\n                pass\n\n    if out.get("vpr") is None:\n        for c in (plugin_details.get("vpr"), plugin_details.get("vpr_score"), ri.get("vpr"), ri.get("vpr_score")):\n            if c is None:\n                continue\n            if isinstance(c, dict):\n                c = c.get("score") or c.get("value")\n            try:\n                out["vpr"] = float(c)\n                break\n            except Exception:\n                pass\n\n    if out.get("vpr_beta") is None:\n        v2 = plugin_details.get("vpr_v2") or ri.get("vpr_v2")\n        if isinstance(v2, dict) and v2.get("score") is not None:\n            try:\n                out["vpr_beta"] = float(v2.get("score"))\n            except Exception:\n                pass\n        elif v2 is not None:\n            try:\n                out["vpr_beta"] = float(v2)\n            except Exception:\n                pass\n\n    # Key drivers suelen ser plugin-level\n    if not out.get("key_drivers"):\n        kd = plugin_details.get("key_drivers") or ri.get("key_drivers")\n        if isinstance(kd, list):\n            out["key_drivers"] = [str(x.get("name") if isinstance(x, dict) else x).strip() for x in kd if x]\n        elif isinstance(kd, str) and kd.strip():\n            out["key_drivers"] = [kd.strip()]\n\n    return out\n\ndef extract_acr_from_asset_details(asset_details: Dict[str, Any]) -> Optional[float]:\n    if not isinstance(asset_details, dict):\n        return None\n\n    # direct keys\n    for k in ("acr_score", "acr", "asset_criticality_rating"):\n        v = asset_details.get(k)\n        if v is None:\n            continue\n        if isinstance(v, dict):\n            v = v.get("score") or v.get("value")\n        try:\n            return float(v)\n        except Exception:\n            pass\n\n    # some tenants nest under "risk_information" or "criticality"\n    for container_key in ("risk_information", "criticality", "criticality_rating", "scores"):\n        c = asset_details.get(container_key)\n        if isinstance(c, dict):\n            for k in ("acr_score", "acr", "asset_criticality_rating", "score"):\n                v = c.get(k)\n                if v is None:\n                    continue\n                if isinstance(v, dict):\n                    v = v.get("score") or v.get("value")\n                try:\n                    return float(v)\n                except Exception:\n                    pass\n\n    # recursive fallback: first acr_score/acr found anywhere (avoid false positives by key name)\n    def walk(obj):\n        if isinstance(obj, dict):\n            for kk, vv in obj.items():\n                if kk in ("acr_score", "acr", "asset_criticality_rating"):\n                    yield vv\n                yield from walk(vv)\n        elif isinstance(obj, list):\n            for it in obj:\n                yield from walk(it)\n\n    for vv in walk(asset_details):\n        if vv is None:\n            continue\n        if isinstance(vv, dict):\n            vv = vv.get("score") or vv.get("value")\n        try:\n            return float(vv)\n        except Exception:\n            continue\n\n    return None\n    for k in ("acr_score", "acr", "asset_criticality_rating"):\n        v = asset_details.get(k)\n        if v is None:\n            continue\n        if isinstance(v, dict):\n            v = v.get("score") or v.get("value")\n        try:\n            return float(v)\n        except Exception:\n            continue\n    return None\n\n\n# -------------------------\n# Renderers\n# -------------------------\ndef render_severity_bars(tag_label: str, severity_counts: Dict[str, int], out_path: str) -> None:\n    data = {k: int(severity_counts.get(k, 0)) for k in SEVERITY_ORDER}\n    total = sum(data.values())\n\n    fig, ax = plt.subplots(figsize=SEV_IMG_SIZE, dpi=IMG_DPI)\n    fig.patch.set_facecolor("white")\n    ax.set_facecolor("white")\n\n    xs = list(range(len(SEVERITY_ORDER)))\n    ys = [data[k] for k in SEVERITY_ORDER]\n    colors = [SEVERITY_COLORS[k] for k in SEVERITY_ORDER]\n\n    bars = ax.bar(xs, ys, color=colors, width=0.62, edgecolor="#E5E7EB", linewidth=1)\n\n    y_max = max(ys) if ys else 0\n    y_lim = max(1, int(y_max * 1.25) if y_max > 0 else 1)\n    ax.set_ylim(0, y_lim)\n\n    for b in bars:\n        h = b.get_height()\n        ax.text(\n            b.get_x() + b.get_width() / 2,\n            h + (y_lim * 0.03),\n            str(int(h)),\n            ha="center",\n            va="bottom",\n            fontsize=12,\n            fontweight="bold",\n            color="#111827"\n        )\n\n    ax.set_xticks(xs)\n    ax.set_xticklabels([SEVERITY_LABELS[k] for k in SEVERITY_ORDER], fontsize=11)\n\n    ax.spines["top"].set_visible(False)\n    ax.spines["right"].set_visible(False)\n    ax.spines["left"].set_color("#E5E7EB")\n    ax.spines["bottom"].set_color("#E5E7EB")\n    ax.tick_params(axis="y", colors="#6B7280")\n    ax.grid(axis="y", linestyle="-", linewidth=0.8, color="#F3F4F6")\n    ax.set_axisbelow(True)\n\n    # Header fijo y con MUCHO espacio\n    fig.text(0.02, 0.975, "Vulnerabilities by Severity",\n             ha="left", va="top", fontsize=22, fontweight="bold", color="#0F172A")\n    fig.text(0.02, 0.890, tag_label,\n             ha="left", va="top", fontsize=12.5, color="#334155")\n    fig.text(0.98, 0.890, f"Total: {total}",\n             ha="right", va="top", fontsize=12.5, color="#334155")\n\n    fig.subplots_adjust(top=0.78, left=0.06, right=0.98, bottom=0.16)\n\n    fig.savefig(out_path, dpi=IMG_DPI, facecolor="white")\n    plt.close(fig)\n\ndef render_top10_list(tag_label: str, top10: List[Dict[str, Any]], out_path: str) -> None:\n    fig = plt.figure(figsize=TOP10_IMG_SIZE, dpi=IMG_DPI)\n    ax = fig.add_axes([0, 0, 1, 1])\n    ax.set_axis_off()\n\n    ax.add_patch(Rectangle((0, 0.92), 1, 0.08, transform=ax.transAxes, facecolor="#0F172A", edgecolor="none"))\n    ax.text(0.02, 0.956, "Top 10 vulnerabilities (by VPR)", transform=ax.transAxes,\n            fontsize=16, fontweight="bold", color="white", va="center")\n    ax.text(0.98, 0.956, tag_label, transform=ax.transAxes,\n            fontsize=11, color="#E5E7EB", va="center", ha="right")\n\n    # Column headers (SIN Instances)\n    ax.add_patch(Rectangle((0.02, 0.86), 0.96, 0.05, transform=ax.transAxes, facecolor="#F1F5F9", edgecolor="#E2E8F0"))\n    cols = [\n        ("#", 0.035, "left"),\n        ("Severity", 0.085, "left"),\n        ("Vulnerability", 0.19, "left"),\n        ("VPR", 0.86, "right"),\n        ("Assets", 0.955, "right"),\n    ]\n    for name, x, ha in cols:\n        ax.text(x, 0.885, name, transform=ax.transAxes, fontsize=11, fontweight="bold", color="#334155", ha=ha, va="center")\n\n    start_y = 0.84\n    row_h = 0.075\n    left = 0.02\n    width = 0.96\n\n    if not top10:\n        ax.add_patch(Rectangle((left, start_y - row_h), width, row_h, transform=ax.transAxes,\n                               facecolor="white", edgecolor="#E2E8F0"))\n        ax.text(0.5, start_y - row_h/2, "No vulnerabilities with VPR were found for this tag.",\n                transform=ax.transAxes, ha="center", va="center", fontsize=12, color="#475569")\n        fig.savefig(out_path, dpi=IMG_DPI, facecolor="white")\n        plt.close(fig)\n        return\n\n    for i, item in enumerate(top10, start=1):\n        y_top = start_y - (i - 1) * row_h\n        y0 = y_top - row_h\n\n        bg = "#FFFFFF" if i % 2 == 1 else "#F8FAFC"\n        ax.add_patch(Rectangle((left, y0), width, row_h, transform=ax.transAxes, facecolor=bg, edgecolor="#E2E8F0"))\n\n        sev = sev_from_rank(int(item.get("max_severity_rank", -1)))\n        sev_color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["none"])\n\n        ax.add_patch(Rectangle((left, y0), 0.008, row_h, transform=ax.transAxes, facecolor=sev_color, edgecolor="none"))\n\n        ax.text(0.035, y0 + row_h/2, str(i), transform=ax.transAxes, ha="left", va="center",\n                fontsize=11, fontweight="bold", color="#0F172A")\n\n        pill_x, pill_y = 0.075, y0 + row_h * 0.26\n        pill_w, pill_h = 0.085, row_h * 0.48\n        ax.add_patch(FancyBboxPatch(\n            (pill_x, pill_y), pill_w, pill_h,\n            boxstyle="round,pad=0.012,rounding_size=0.015",\n            transform=ax.transAxes,\n            facecolor=sev_color,\n            edgecolor="none"\n        ))\n        ax.text(pill_x + pill_w/2, pill_y + pill_h/2, SEVERITY_LABELS.get(sev, "None"),\n                transform=ax.transAxes, ha="center", va="center", fontsize=9.5, fontweight="bold", color="white")\n\n        name = truncate(item.get("name", "Unknown plugin"), 95)\n        ax.text(0.19, y0 + row_h/2, name, transform=ax.transAxes, ha="left", va="center",\n                fontsize=11, color="#111827")\n\n        vpr = item.get("vpr")\n        vpr_beta = item.get("vpr_beta")\n        eff = vpr if vpr is not None else vpr_beta\n        vpr_txt = f"{float(eff):.1f}" if eff is not None else "—"\n        ax.text(0.86, y0 + row_h/2, vpr_txt, transform=ax.transAxes, ha="right", va="center",\n                fontsize=11, fontweight="bold", color="#0F172A")\n\n        assets = item.get("affected_assets", 0) or 0\n        ax.text(0.955, y0 + row_h/2, str(int(assets)), transform=ax.transAxes, ha="right", va="center",\n                fontsize=11, color="#0F172A")\n\n    ax.text(0.02, 0.02, "Assets = distinct assets affected (unique asset.uuid).",\n            transform=ax.transAxes, fontsize=9.5, color="#64748B", ha="left", va="bottom")\n\n    fig.savefig(out_path, dpi=IMG_DPI, facecolor="white")\n    plt.close(fig)\n\ndef render_spotlight(tag_label: str, finding: Dict[str, Any], out_path: str) -> None:\n    title = finding.get("name") or "Unknown vulnerability"\n    fid = finding.get("finding_id") or "—"\n    pid = finding.get("plugin_id") or "—"\n    asset_label = finding.get("asset_label") or "—"\n    sev = finding.get("severity") or "none"\n    sev_lbl = SEVERITY_LABELS.get(sev, "None")\n    sev_color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["none"])\n\n    vpr = finding.get("vpr")\n    vpr_beta = finding.get("vpr_beta")\n    cvss3 = finding.get("cvss3")\n    acr = finding.get("acr")  # ACR del asset representativo\n    kds = finding.get("key_drivers") or []\n    if isinstance(kds, str):\n        kds = [kds]\n    kd_text = " • ".join([truncate(str(x), 34) for x in kds[:2]]) if kds else "—"\n    if len(kds) > 2:\n        kd_text = kd_text + f"  +{len(kds)-2}"\n\n    solution = finding.get("solution")\n    workaround = finding.get("workaround")\n    gen = finding.get("generated_at") or now_utc_iso()\n\n    fig = plt.figure(figsize=SPOT_IMG_SIZE, dpi=IMG_DPI)\n    ax = fig.add_axes([0, 0, 1, 1])\n    ax.set_axis_off()\n    fig.patch.set_facecolor("#F8FAFC")\n\n    # Card\n    ax.add_patch(FancyBboxPatch(\n        (0.02, 0.03), 0.96, 0.94,\n        boxstyle="round,pad=0.012,rounding_size=0.02",\n        transform=ax.transAxes,\n        facecolor="white",\n        edgecolor="#E2E8F0",\n        linewidth=1.2\n    ))\n\n    # Header\n    ax.text(0.06, 0.93, truncate(title, 70), transform=ax.transAxes,\n            ha="left", va="center", fontsize=18, fontweight="bold", color="#0F172A")\n\n    ax.text(0.06, 0.892, f"Finding ID: {fid}", transform=ax.transAxes,\n            ha="left", va="center", fontsize=11.5, color="#475569")\n    ax.text(0.06, 0.862, f"Nessus Plugin ID: {pid}", transform=ax.transAxes,\n            ha="left", va="center", fontsize=11.5, color="#475569")\n\n    # Badges\n    badge_y = 0.775\n    badge_h = 0.038\n    badge_gap = 0.012\n\n    def badge(x, text, bg):\n        w = 0.09 + (len(text) * 0.006)\n        ax.add_patch(FancyBboxPatch(\n            (x, badge_y), w, badge_h,\n            boxstyle="round,pad=0.006,rounding_size=0.02",\n            transform=ax.transAxes, facecolor=bg, edgecolor="none"\n        ))\n        ax.text(x + w/2, badge_y + badge_h/2, text, transform=ax.transAxes,\n                ha="center", va="center", fontsize=11, fontweight="bold", color="white")\n        return x + w + badge_gap\n\n    x0 = 0.06\n    x0 = badge(x0, sev_lbl.upper(), sev_color)\n    x0 = badge(x0, "ACTIVE", "#2563EB")\n\n    # Metric cards (re-layout para evitar labels pegados)\n    cards_y = 0.585\n    cards_h = 0.17\n    left = 0.06\n    right = 0.94\n    gap = 0.012\n\n    names = ["VPR", "VPR (Beta)", "CVSSv3", "ACR"]\n    values = [\n        ("—" if vpr is None else f"{float(vpr):.1f}", "/10"),\n        ("—" if vpr_beta is None else f"{float(vpr_beta):.1f}", "/10"),\n        ("—" if cvss3 is None else f"{float(cvss3):.1f}", "/10"),\n        ("—" if acr is None else f"{float(acr):.1f}", "/10"),\n    ]\n\n    n = len(names)\n    card_w = (right - left - gap * (n - 1)) / n\n\n    # posiciones relativas dentro de la card (evita que el label se encime con el número grande)\n    label_y = cards_y + cards_h * 0.93\n    value_y = cards_y + cards_h * 0.56\n    denom_y = cards_y + cards_h * 0.56\n    bar_y = cards_y + cards_h * 0.20\n    bar_h = cards_h * 0.07  # ~0.012\n\n    for i in range(n):\n        cx = left + i * (card_w + gap)\n        ax.add_patch(FancyBboxPatch(\n            (cx, cards_y), card_w, cards_h,\n            boxstyle="round,pad=0.012,rounding_size=0.02",\n            transform=ax.transAxes,\n            facecolor="white",\n            edgecolor="#E2E8F0",\n            linewidth=1.2\n        ))\n        ax.text(cx + 0.02, label_y, names[i], transform=ax.transAxes,\n                ha="left", va="top", fontsize=11, fontweight="bold", color="#334155")\n\n        val, denom = values[i]\n        if names[i] == "Key Drivers":\n            ax.text(cx + 0.02, cards_y + cards_h * 0.35, wrap_lines(val, 22, 2), transform=ax.transAxes,\n                    ha="left", va="center", fontsize=11.2, color="#0F172A")\n        else:\n            ax.text(cx + 0.02, value_y, val, transform=ax.transAxes,\n                    ha="left", va="center", fontsize=(18 if val == "—" else 22),\n                    fontweight="bold", color="#0F172A")\n            ax.text(cx + card_w - 0.02, denom_y, denom, transform=ax.transAxes,\n                    ha="right", va="center", fontsize=11.2, color="#64748B")\n\n            # mini bar\n            ax.add_patch(FancyBboxPatch(\n                (cx + 0.02, bar_y), card_w - 0.04, bar_h,\n                boxstyle="round,pad=0.004,rounding_size=0.01",\n                transform=ax.transAxes, facecolor="#E2E8F0", edgecolor="none"\n            ))\n            try:\n                vv = float(val) if val != "—" else 0.0\n                frac = max(0.0, min(1.0, vv / 10.0))\n            except Exception:\n                frac = 0.0\n\n            fill_color = "#F59E0B" if frac < 0.7 else "#DC2626"\n            ax.add_patch(FancyBboxPatch(\n                (cx + 0.02, bar_y), (card_w - 0.04) * frac, bar_h,\n                boxstyle="round,pad=0.004,rounding_size=0.01",\n                transform=ax.transAxes, facecolor=fill_color, edgecolor="none"\n            ))\n\n    # Divider\n    ax.add_line(plt.Line2D([0.06, 0.94], [0.545, 0.545], transform=ax.transAxes, color="#E2E8F0", linewidth=1.2))\n\n    # Fixes\n    ax.text(0.06, 0.505, "Fixes", transform=ax.transAxes,\n            ha="left", va="center", fontsize=14.5, fontweight="bold", color="#0F172A")\n\n    ax.text(0.06, 0.465, "Solution", transform=ax.transAxes,\n            ha="left", va="center", fontsize=12.5, fontweight="bold", color="#0F172A")\n    ax.text(0.06, 0.435, wrap_lines(solution, 94, 3), transform=ax.transAxes,\n            ha="left", va="top", fontsize=12.2, color="#475569")\n\n    ax.text(0.06, 0.32, "Workaround", transform=ax.transAxes,\n            ha="left", va="center", fontsize=12.5, fontweight="bold", color="#0F172A")\n    ax.text(0.06, 0.29, wrap_lines(workaround, 94, 3), transform=ax.transAxes,\n            ha="left", va="top", fontsize=12.2, color="#475569")\n\n    ax.text(0.06, 0.06, f"{tag_label}  •  Generated: {gen}", transform=ax.transAxes,\n            ha="left", va="center", fontsize=10.5, color="#64748B")\n\n    fig.savefig(out_path, dpi=IMG_DPI, facecolor=fig.get_facecolor())\n    plt.close(fig)\n\n\n# -------------------------\n# Per-tag processing\n# -------------------------\ndef process_tag(sess: requests.Session, target: Dict[str, str]) -> Dict[str, Any]:\n    tag_category = target["tag_category"]\n    tag_value = target["tag_value"]\n    tid = target["id"]\n\n    filters: Dict[str, Any] = {\n        "state": ["OPEN", "REOPENED"],\n        f"tag.{tag_category}": [tag_value],\n    }\n    if FORCE_NO_30D_LIMIT:\n        filters["last_found"] = 0\n\n    export_uuid = create_vulns_export(sess, filters=filters, num_assets=5000)\n\n    while True:\n        st = export_status(sess, export_uuid)\n        status = st.get("status")\n        if status == "FINISHED":\n            break\n        if status in ("ERROR", "CANCELLED"):\n            raise RuntimeError(f"{tid}: export {export_uuid} terminó en {status}: {st}")\n        time.sleep(4)\n\n    chunk_ids = st.get("chunks_available", []) or []\n    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "none": 0}\n    seen_asset_plugin = set()  # (asset.uuid, plugin.id)\n\n    plugin_assets = defaultdict(set)       # pid -> set(asset.uuid)\n    plugin_instances = defaultdict(int)    # pid -> count de (asset+plugin) únicos\n    plugin_max_vpr: Dict[int, Optional[float]] = {}\n    plugin_max_vpr_beta: Dict[int, Optional[float]] = {}\n    plugin_name: Dict[int, str] = {}\n    plugin_max_sev_rank = defaultdict(lambda: -1)\n\n    spotlight_best_row_by_plugin: Dict[int, Dict[str, Any]] = {}\n\n    for cid in chunk_ids:\n        raw = download_chunk_raw(sess, export_uuid, cid)\n        for row in iter_records_from_chunk(raw):\n            a_uuid = get_asset_uuid(row)\n            pid = get_plugin_id(row)\n            if not a_uuid or not pid:\n                continue\n\n            ap_key = (a_uuid, pid)\n            if ap_key in seen_asset_plugin:\n                continue\n            seen_asset_plugin.add(ap_key)\n\n            sev = normalize_severity(row)\n            if sev not in severity_counts:\n                sev = "none"\n            severity_counts[sev] += 1\n\n            plugin_assets[pid].add(a_uuid)\n            plugin_instances[pid] += 1\n            plugin_name[pid] = get_plugin_name(row)\n\n            vpr, vpr_beta = get_vpr_and_beta(row)\n\n            if vpr is not None:\n                prev = plugin_max_vpr.get(pid)\n                if prev is None or vpr > prev:\n                    plugin_max_vpr[pid] = vpr\n\n            if vpr_beta is not None:\n                prevb = plugin_max_vpr_beta.get(pid)\n                if prevb is None or vpr_beta > prevb:\n                    plugin_max_vpr_beta[pid] = vpr_beta\n\n            r = sev_rank(sev)\n            if r > plugin_max_sev_rank[pid]:\n                plugin_max_sev_rank[pid] = r\n\n            # Guarda un row representativo por plugin (prefiere el que tenga más datos útiles)\n            cur = spotlight_best_row_by_plugin.get(pid)\n            score_row = 0\n            if vpr is not None: score_row += 2\n            if vpr_beta is not None: score_row += 1\n            if get_cvss3(row) is not None: score_row += 1\n            if get_solution_workaround(row)[0]: score_row += 1\n            if get_key_drivers(row): score_row += 1\n            if get_asset_acr_from_row(row) is not None: score_row += 1\n\n            if cur is None:\n                spotlight_best_row_by_plugin[pid] = row\n            else:\n                cur_score = 0\n                cv = get_vpr_and_beta(cur)\n                if cv[0] is not None: cur_score += 2\n                if cv[1] is not None: cur_score += 1\n                if get_cvss3(cur) is not None: cur_score += 1\n                if get_solution_workaround(cur)[0]: cur_score += 1\n                if get_key_drivers(cur): cur_score += 1\n                if get_asset_acr_from_row(cur) is not None: cur_score += 1\n                if score_row > cur_score:\n                    spotlight_best_row_by_plugin[pid] = row\n\n    plugins: List[Dict[str, Any]] = []\n    for pid, inst_count in plugin_instances.items():\n        plugins.append({\n            "plugin_id": pid,\n            "name": plugin_name.get(pid, "Unknown plugin"),\n            "vpr": plugin_max_vpr.get(pid),\n            "vpr_beta": plugin_max_vpr_beta.get(pid),\n            "max_severity_rank": plugin_max_sev_rank.get(pid, -1),\n            "affected_assets": len(plugin_assets.get(pid, set())),\n            "instances_host_plugin": inst_count,\n        })\n\n    # Top10 por VPR (fallback a VPR Beta)\n    plugins.sort(\n        key=lambda x: (\n            (x.get("vpr") is not None) or (x.get("vpr_beta") is not None),\n            (x.get("vpr") if x.get("vpr") is not None else (x.get("vpr_beta") if x.get("vpr_beta") is not None else -1)),\n            x.get("max_severity_rank", -1),\n            x.get("affected_assets", 0),\n            x.get("instances_host_plugin", 0),\n        ),\n        reverse=True\n    )\n    top10 = plugins[:10]\n\n    # Spotlight: más crítico dentro del Top10, luego por VPR efectivo\n    spotlight = None\n    if top10:\n        top10_sorted = sorted(\n            top10,\n            key=lambda x: (x.get("max_severity_rank", -1),\n                           (x.get("vpr") if x.get("vpr") is not None else (x.get("vpr_beta") or -1))),\n            reverse=True\n        )\n        chosen = top10_sorted[0]\n        pid = int(chosen["plugin_id"])\n        row = spotlight_best_row_by_plugin.get(pid, {})\n\n        sev = sev_from_rank(int(chosen.get("max_severity_rank", -1)))\n        vpr = chosen.get("vpr")\n        vpr_beta = chosen.get("vpr_beta")\n        cvss3 = get_cvss3(row)\n        kds = get_key_drivers(row)\n        sol, wor = get_solution_workaround(row)\n        fid = get_finding_id(row)\n\n        asset_uuid = get_asset_uuid(row) or ""\n        asset_label = get_asset_label(row)\n        acr = get_asset_acr_from_row(row)\n\n        # Si el export no trae ACR, intentamos enriquecer del asset endpoint (solo para spotlight)\n        if acr is None and asset_uuid:\n            asset_id = get_asset_id(row)\n            ad = fetch_asset_details(sess, asset_uuid, asset_id)\n            acr = extract_acr_from_asset_details(ad)\n\n        spotlight = {\n            "name": chosen.get("name"),\n            "finding_id": fid,\n            "plugin_id": pid,\n            "severity": sev,\n            "vpr": vpr,\n            "vpr_beta": vpr_beta,\n            "cvss3": cvss3,\n            "acr": acr,\n            "key_drivers": kds,\n            "solution": sol,\n            "workaround": wor,\n            "asset_label": asset_label,\n            "generated_at": now_utc_iso(),\n        }\n\n        # Enriquecemos SOLO lo plugin-level: solution/workaround/cvss3/vpr/key drivers\n        details = fetch_plugin_details(sess, pid)\n        spotlight = enrich_from_plugin_details(spotlight, details)\n\n    return {\n        "id": tid,\n        "tag_category": tag_category,\n        "tag_value": tag_value,\n        "generated_at": now_utc_iso(),\n        "total_vulns": sum(severity_counts.values()),\n        "severity_counts": severity_counts,\n        "top10_by_vpr": top10,\n        "spotlight": spotlight,\n    }\n\n\n# -------------------------\n# Main\n# -------------------------\ndef main():\n    sess = make_session()\n    ensure_dir(OUTPUT_ROOT)\n\n    print(f"[INFO] Descubriendo tags en categorías: {\', \'.join(WANTED_CATEGORIES)} ...")\n    targets = discover_targets(sess)\n    print(f"[INFO] Tags descubiertas: {len(targets)}")\n\n    with open(os.path.join(OUTPUT_ROOT, "targets_discovered.json"), "w", encoding="utf-8") as f:\n        json.dump(targets, f, ensure_ascii=False, indent=2)\n\n    for i, t in enumerate(targets, start=1):\n        tid = t["id"]\n        tag_label = f"{t[\'tag_category\']} = {t[\'tag_value\']}"\n        print(f"[{i}/{len(targets)}] Procesando {tag_label}  ({tid})")\n\n        try:\n            res = process_tag(sess, t)\n            sev_img = os.path.join(OUTPUT_ROOT, f"{tid}_severity.png")\n            top_img = os.path.join(OUTPUT_ROOT, f"{tid}_top10.png")\n            sp_img = os.path.join(OUTPUT_ROOT, f"{tid}_spotlight.png")\n\n            render_severity_bars(tag_label, res["severity_counts"], sev_img)\n            render_top10_list(tag_label, res["top10_by_vpr"], top_img)\n\n            if res.get("spotlight"):\n                render_spotlight(tag_label, res["spotlight"], sp_img)\n                print(f"  [OK] total={res[\'total_vulns\']} -> {os.path.basename(sev_img)}, {os.path.basename(top_img)}, {os.path.basename(sp_img)}")\n            else:\n                print(f"  [OK] total={res[\'total_vulns\']} -> {os.path.basename(sev_img)}, {os.path.basename(top_img)} (spotlight: none)")\n\n        except Exception as e:\n            print(f"  [ERR] {e}")\n\n        if SLEEP_BETWEEN_EXPORTS_SECONDS > 0:\n            time.sleep(SLEEP_BETWEEN_EXPORTS_SECONDS)\n\n    print(f"[DONE] Imágenes en: {OUTPUT_ROOT}")\n\n\nif __name__ == "__main__":\n    main()',
    "tenable_identity": '#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n"""\nTenable Identity / Tenable One (Exposure Management) - KPI donuts\n\nEste script puede trabajar en 2 modos:\n\n1) Tenable One / Exposure Management (cloud.tenable.com):\n   - Usa el endpoint: POST /api/v1/t1/inventory/assets/search\n   - Ideal si tus KPIs vienen de Global Search / Inventory (consultas tipo "Assets AS ACCOUNT ...")\n\n   Requiere variables de entorno (recomendado):\n     TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY\n   (Opcional) TENABLE_BASE_URL (default https://cloud.tenable.com)\n\n2) Tenable Identity Exposure (tenable.ad):\n   - Usa checkers/deviances para contar.\n   - Solo como fallback si NO defines TENABLE_ACCESS_KEY/TENABLE_SECRET_KEY.\n\nSalida:\n  identity_exposure_donuts_4k.png\n"""\n\nimport os\nimport sys\nfrom pathlib import Path\n\nimport requests\nfrom PIL import Image, ImageDraw, ImageFont\n\n# =========================================================\n# CONFIG IMAGEN\n# =========================================================\nOUT_FILE = "identity_exposure_donuts_4k.png"\nW4, H4 = 3840, 2160  # 4K\nSCALE = 2            # se renderiza al doble y luego se hace downscale\n\n# =========================================================\n# TENABLE ONE / EXPOSURE MANAGEMENT (cloud.tenable.com)\n# =========================================================\nTENABLE_BASE_URL = os.getenv("TENABLE_BASE_URL", "https://cloud.tenable.com").rstrip("/")\n# Tus queries (tal cual las usas en el dashboard):\nT1_QUERIES = {\n    "Dormant Account": \'Assets AS ACCOUNT WITH Weakness HAS ( detection_code contains "DORMANT-" OR detection_code contains "C-SLEEPING-ACCOUNTS" )\',\n    "Domain Admin": \'Assets AS ACCOUNT WITH Relationship = ACCOUNT -> GROUP HAS directory_object_sid contains "S-1-5-21-%-512"\',\n    "Guest Account": \'Assets AS ACCOUNT HAS ( account_user_type = "guest" OR directory_object_sid contains "S-1-5-21-%-501" )\',\n}\n\n# =========================================================\n# TENABLE IDENTITY EXPOSURE (tenable.ad) - FALLBACK\n# =========================================================\nTENANT_HOST = os.getenv("IE_TENANT_HOST", "793ae199.tenable.ad").strip()\nIE_API_KEY = os.getenv("IE_API_KEY", "").strip()  # si lo vas a usar como fallback\nIE_BASE_URL = f"https://{TENANT_HOST}/api"\n\nTIMEOUT = 60\n\nKPI_LABELS = ["Dormant Account", "Domain Admin", "Guest Account"]\n\n# =========================================================\n# HTTP helpers\n# =========================================================\ndef _request_json(method: str, url: str, headers: dict, *, params=None, json_body=None, timeout=TIMEOUT):\n    r = requests.request(method, url, headers=headers, params=params, json=json_body, timeout=timeout)\n    if r.status_code >= 400:\n        try:\n            err = r.json()\n        except Exception:\n            err = r.text\n        raise RuntimeError(f"HTTP {r.status_code} {method} {url}\\n{err}")\n    if r.status_code == 204:\n        return None\n    try:\n        return r.json()\n    except Exception:\n        return None\n\ndef to_req(method: str, path: str, *, params=None, json_body=None):\n    url = f"{TENABLE_BASE_URL}{path}"\n    headers = {\n        "accept": "application/json",\n        "content-type": "application/json",\n        "X-ApiKeys": f"accessKey={TENABLE_ACCESS_KEY}; secretKey={TENABLE_SECRET_KEY}",\n    }\n    return _request_json(method, url, headers, params=params, json_body=json_body)\n\ndef ie_req(method: str, path: str, *, params=None, json_body=None):\n    url = f"{IE_BASE_URL}{path}"\n    headers = {\n        "accept": "application/json",\n        "x-api-key": IE_API_KEY,\n    }\n    return _request_json(method, url, headers, params=params, json_body=json_body)\n\ndef unwrap_items(data):\n    if data is None:\n        return []\n    if isinstance(data, list):\n        return data\n    if isinstance(data, dict):\n        for k in ("items", "data", "results"):\n            if k in data and isinstance(data[k], list):\n                return data[k]\n    return []\n\ndef extract_total(resp: dict):\n    """Intenta extraer \'total\' de respuestas con distintos formatos."""\n    if not isinstance(resp, dict):\n        return None\n    # top-level\n    for k in ("total", "total_count", "totalCount", "count", "hits"):\n        if k in resp and isinstance(resp[k], int):\n            return resp[k]\n        if k in resp and isinstance(resp[k], (str, float)) and str(resp[k]).isdigit():\n            return int(resp[k])\n    # nested\n    for container_key in ("pagination", "page", "meta", "stats"):\n        c = resp.get(container_key)\n        if isinstance(c, dict):\n            for k in ("total", "total_count", "totalCount", "count", "hits", "total_items", "totalItems"):\n                if k in c and isinstance(c[k], int):\n                    return c[k]\n                if k in c and isinstance(c[k], (str, float)) and str(c[k]).isdigit():\n                    return int(c[k])\n    return None\n\n# =========================================================\n# TENABLE ONE: contar usando Inventory Search Assets\n# =========================================================\ndef t1_assets_count(query_text: str) -> int:\n    """\n    Cuenta assets usando POST /api/v1/t1/inventory/assets/search.\n    - Usa limit=1 para obtener el total sin paginar (cuando el API lo devuelve).\n    - Si no viene total, hace paginación.\n    """\n    # Nota: el endpoint está documentado como beta.  \ue200cite\ue202turn23view0\ue201\n    path = "/api/v1/t1/inventory/assets/search"\n\n    # Primero intentamos con modos comunes. Si uno falla, probamos el siguiente.\n    modes_to_try = ["advanced", "tql", "simple"]\n    last_err = None\n\n    for mode in modes_to_try:\n        try:\n            body = {"query": {"text": query_text, "mode": mode}}\n            # Pedimos 1 solo asset, esperando que el API devuelva también el total.\n            resp = to_req("POST", path, params={"offset": 0, "limit": 1}, json_body=body)\n            total = extract_total(resp)\n            if total is not None:\n                return total\n\n            # Si no hay total, hacemos paginación (offset/limit)\n            limit = 500\n            offset = 0\n            seen = 0\n            while True:\n                resp_page = to_req("POST", path, params={"offset": offset, "limit": limit}, json_body=body)\n                items = unwrap_items(resp_page)\n                if not items:\n                    break\n                seen += len(items)\n                if len(items) < limit:\n                    break\n                offset += limit\n            return seen\n        except Exception as e:\n            last_err = e\n            continue\n\n    raise RuntimeError(f"No se pudo ejecutar la búsqueda en Tenable One. Último error: {last_err}")\n\n# =========================================================\n# IDENTITY EXPOSURE fallback (lo que ya tenías)\n# =========================================================\ndef get_profiles():\n    data = ie_req("GET", "/profiles")\n    return unwrap_items(data)\n\ndef get_checkers(profile_id):\n    data = ie_req("GET", f"/profiles/{profile_id}/checkers")\n    return unwrap_items(data)\n\ndef count_paged_ie(path, payload, per_page=200):\n    total = 0\n    page = 1\n    while True:\n        params = {"page": page, "perPage": per_page}\n        data = ie_req("POST", path, params=params, json_body=payload)\n        items = unwrap_items(data)\n        if not items:\n            break\n        total += len(items)\n        page += 1\n    return total\n\ndef count_deviances_for_checker(profile_id, checker_id):\n    # Expression vacía “segura” (evita 500 en algunos tenants)\n    payload = {"expression": {"OR": [{}]}}\n    path = f"/profiles/{profile_id}/checkers/{checker_id}/deviances"\n    return count_paged_ie(path, payload)\n\n# =========================================================\n# Imagen\n# =========================================================\ndef fmt_compact(n):\n    if n is None:\n        return "N/A"\n    try:\n        n = int(n)\n    except Exception:\n        return str(n)\n    if n >= 1_000_000:\n        return f"{n/1_000_000:.1f}M".replace(".0", "")\n    if n >= 1_000:\n        return f"{n/1_000:.1f}k".replace(".0", "")\n    return str(n)\n\ndef load_font(size):\n    for name in ("arial.ttf", "segoeui.ttf", "calibri.ttf"):\n        try:\n            return ImageFont.truetype(name, size)\n        except Exception:\n            continue\n    return ImageFont.load_default()\n\ndef draw_donut(draw, cx, cy, r, width, center_text, label, scale=2):\n    colors = ["#F7C948", "#F59F00", "#FF922B", "#E03131"]\n    gap = 10\n    n = len(colors)\n    seg = (360 - n * gap) / n\n    start = -90\n\n    bbox = [cx - r, cy - r, cx + r, cy + r]\n    for i, col in enumerate(colors):\n        a0 = start + i * (seg + gap)\n        a1 = a0 + seg\n        draw.arc(bbox, start=a0, end=a1, fill=col, width=width)\n\n    font_big = load_font(int(64 * scale))\n    font_lbl = load_font(int(22 * scale))\n    font_sub = load_font(int(30 * scale))\n\n    tw, th = draw.textbbox((0, 0), center_text, font=font_big)[2:]\n    draw.text((cx - tw / 2, cy - th / 2 - 12 * scale), center_text, fill="#111827", font=font_big)\n\n    lw, lh = draw.textbbox((0, 0), label, font=font_sub)[2:]\n    draw.text((cx - lw / 2, cy + r + 34 * scale), label, fill="#111827", font=font_sub)\n\n    sub = "Total"\n    sw, sh = draw.textbbox((0, 0), sub, font=font_lbl)[2:]\n    draw.text((cx - sw / 2, cy + r + 78 * scale), sub, fill="#6B7280", font=font_lbl)\n\ndef make_image(counts):\n    W, H = W4 * SCALE, H4 * SCALE\n    img = Image.new("RGB", (W, H), "white")\n    d = ImageDraw.Draw(img)\n\n    title = "Identity Exposure KPIs"\n    title_font = load_font(int(56 * SCALE))\n    tw, th = d.textbbox((0, 0), title, font=title_font)[2:]\n    d.text(((W - tw) / 2, 120 * SCALE), title, fill="#111827", font=title_font)\n\n    centers_x = [W * 0.17, W * 0.50, W * 0.83]\n    cy = H * 0.52\n    r = int(340 * SCALE)\n    ring_w = int(34 * SCALE)\n\n    for i, label in enumerate(KPI_LABELS):\n        val = counts.get(label)\n        draw_donut(\n            d,\n            int(centers_x[i]),\n            int(cy),\n            r,\n            ring_w,\n            fmt_compact(val) if val is not None else "N/A",\n            label,\n            scale=SCALE,\n        )\n\n    img_4k = img.resize((W4, H4), resample=Image.Resampling.LANCZOS)\n    img_4k.save(OUT_FILE, "PNG", optimize=True)\n\n# =========================================================\n# Main\n# =========================================================\ndef main():\n    # Prioridad: Tenable One si hay llaves\n    if TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY:\n        print(f"Modo: Tenable One / Exposure Management ({TENABLE_BASE_URL})")\n        counts = {}\n        for label in KPI_LABELS:\n            q = T1_QUERIES[label]\n            c = t1_assets_count(q)\n            counts[label] = c\n        print("Counts:", counts)\n        make_image(counts)\n        print("OK ->", OUT_FILE)\n        return\n\n    # Fallback: Identity Exposure (solo si hay IE_API_KEY)\n    if not IE_API_KEY:\n        print("ERROR: No hay llaves de Tenable One (TENABLE_ACCESS_KEY/TENABLE_SECRET_KEY) y tampoco IE_API_KEY.")\n        print("Si tus números vienen del dashboard con queries \'Assets AS ACCOUNT ...\', necesitas usar Tenable One.")\n        sys.exit(2)\n\n    print(f"Modo: Identity Exposure ({TENANT_HOST})")\n    about = ie_req("GET", "/about")\n    print("OK /about:", about)\n\n    profiles = get_profiles()\n    if not profiles:\n        raise RuntimeError("No se encontraron profiles en Identity Exposure.")\n\n    profile_id = str(profiles[0].get("id"))\n    print("Profile seleccionado:", profile_id)\n\n    # Nota: este fallback seguirá mostrando números distintos si comparas contra el dashboard de Tenable One.\n    # Usa los checkers “más cercanos” a tu caso actual.\n    wanted = {\n        "Dormant Account": "C-SLEEPING-ACCOUNTS",\n        "Guest Account": "C-GUEST-ACCOUNT",\n        # "Domain Admin" aquí depende del checker que uses realmente. Este era el que te estaba saliendo (AdminCount...).\n        "Domain Admin": "C-ADMINCOUNT-ACCOUNT-PROPS",\n    }\n\n    checkers = get_checkers(profile_id)\n    codename_to_id = {c.get("codename"): c.get("id") for c in checkers if c.get("codename") and c.get("id")}\n\n    counts = {}\n    for label in KPI_LABELS:\n        codename = wanted.get(label)\n        cid = codename_to_id.get(codename)\n        if not cid:\n            counts[label] = None\n            continue\n        counts[label] = count_deviances_for_checker(profile_id, cid)\n\n    print("Counts:", counts)\n    make_image(counts)\n    print("OK ->", OUT_FILE)\n\nif __name__ == "__main__":\n    main()\n',
}


def _load_embedded_module(key: str) -> Dict[str, Any]:
    """Ejecuta el source del módulo en un namespace aislado y lo devuelve."""
    if key not in MODULE_SOURCES:
        raise KeyError(key)

    ns: Dict[str, Any] = {
        "__name__": f"_embedded_{key}",   # evita ejecutar if __name__ == "__main__"
        "__file__": f"<embedded:{key}>",
        "__package__": None,
        "TENABLE_BASE_URL": TENABLE_BASE_URL,
        "TENABLE_ACCESS_KEY": TENABLE_ACCESS_KEY,
        "TENABLE_SECRET_KEY": TENABLE_SECRET_KEY,
    }
    exec(MODULE_SOURCES[key], ns, ns)
    return ns



def _run_module(ns: Dict[str, Any], argv_for_module: list[str]) -> int:
    """Ejecuta main() del módulo con sys.argv aislado."""
    main_fn = ns.get("main")
    if not callable(main_fn):
        raise RuntimeError("El módulo embebido no expone main()")

    old_argv = sys.argv[:]
    try:
        sys.argv = [old_argv[0]] + argv_for_module
        main_fn()
        return 0
    except SystemExit as e:
        # algunos módulos hacen SystemExit
        code = e.code if isinstance(e.code, int) else 0
        return int(code)
    finally:
        sys.argv = old_argv



# =========================================================
# EJECUCIÓN AUTOMÁTICA (sin parámetros)
# =========================================================

import shutil
import time
import gzip
import json
from datetime import datetime, timezone


def _safe_fs_name(s: str) -> str:
    """Misma lógica que los scripts originales (no cambia nombres salvo caracteres inválidos)."""
    import re as _re
    s = (s or "").strip()
    s = _re.sub(r'[<>:"/\\|?*\x00-\x1F]', "_", s)
    s = _re.sub(r"\s+", " ", s).strip()
    s = s.rstrip(". ")
    return (s[:160] if len(s) > 160 else s) or "unnamed"


def _unified_out_dir() -> str:
    """
    Directorio base donde TODOS los módulos guardan resultados.
    Puedes sobreescribirlo con variable de entorno:
      TENABLE_REPORTS_OUT_DIR
    """
    override = os.getenv("TENABLE_REPORTS_OUT_DIR", "").strip()
    if override:
        return os.path.abspath(override)
    # Por defecto: carpeta mensual
    return os.path.abspath(os.path.join("tenable_reportes", datetime.now(timezone.utc).strftime("%Y-%m")))


def _iter_tag_dirs(base_out: str):
    """Devuelve carpetas tipo: base_out/<categoria>/<valor>/"""
    if not os.path.isdir(base_out):
        return
    for cat in os.listdir(base_out):
        cat_dir = os.path.join(base_out, cat)
        if not os.path.isdir(cat_dir):
            continue
        for val in os.listdir(cat_dir):
            val_dir = os.path.join(cat_dir, val)
            if os.path.isdir(val_dir):
                yield val_dir



def _iter_jsonl_gz_records(path: str):
    """Itera records (dict) desde un .jsonl.gz (1 JSON por línea)."""
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = (line or "").strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                # Línea corrupta / truncada: la ignoramos
                continue


def _tenable_allowed_targets_override() -> Optional[set[tuple[str, str]]]:
    allowed = globals().get("TENABLE_ALLOWED_TARGETS_OVERRIDE")
    if allowed is None:
        return None
    return set(allowed)


def _filter_tag_pairs_by_allowed(tags: List[tuple[str, str]], allowed: Optional[set[tuple[str, str]]]) -> List[tuple[str, str]]:
    if allowed is None:
        return tags
    filtered = [(cat, val) for (cat, val) in tags if (norm(cat), norm(val)) in allowed]
    if filtered:
        return filtered
    print("[WARN] Filtro Tenable sin coincidencias en tags descubiertos; se usarán todos los tags para no romper materialización.")
    return tags


def _is_tag_allowed(cat: str, val: str, allowed: Optional[set[tuple[str, str]]]) -> bool:
    if allowed is None:
        return True
    return (norm(cat), norm(val)) in allowed


def _run_controlesCIS_from_cached_export(ns, dataset_path: str, base_out: str,
                                        rows_to_show: int = 12, assets_per_row: int = 3,
                                        allowed_tenable: Optional[set[tuple[str, str]]] = None) -> int:
    """
    Ejecuta la lógica de 'controlesCIS.py' pero REUSANDO el mismo compliance export
    descargado (compliance_export_all.jsonl.gz), evitando volver a bajar chunks.

    No cambia el diseño: usa exactamente draw_list_image/draw_detail_image del módulo.
    """
    import requests as _requests

    # 1) Descubre tags (llamada ligera)
    session = _requests.Session()
    tags = ns["discover_all_tags"](session)
    tags = _filter_tag_pairs_by_allowed(tags, allowed_tenable)
    if not tags:
        print("[INFO] (cis-host-audits) Sin tags permitidos tras aplicar filtro; no se generarán imágenes por tag.")
    allowed_tags = set(tags)

    # 2) Agrega por tag usando el dataset ya descargado
    records_iter = _iter_jsonl_gz_records(dataset_path)
    aggregated = ns["aggregate"](records_iter, allowed_tags=allowed_tags)

    gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    index = []

    for i, (cat, val) in enumerate(tags, start=1):
        out_dir = os.path.join(base_out, _safe_fs_name(cat), _safe_fs_name(val))
        os.makedirs(out_dir, exist_ok=True)

        tag_label = f"{cat}:{val}"

        audits = aggregated.get((cat, val), {})
        rows = list(audits.values())
        rows.sort(key=lambda x: int(x.get("failed_count", 0)), reverse=True)

        list_png = os.path.join(out_dir, "01_audits_list_4k.png")
        detail_png = os.path.join(out_dir, "02_audit_detail_4k.png")

        ns["draw_list_image"](tag_label, rows, list_png, rows_to_show=rows_to_show, assets_per_row=assets_per_row)

        if rows:
            top = dict(rows[0])
            top["generated_at"] = gen_ts
            ns["draw_detail_image"](tag_label, top, detail_png)
            status = "OK"
        else:
            ns["draw_detail_image"](tag_label, {
                "audit_name": "No audits for this tag",
                "audit_file": "—",
                "plugin_name": "—",
                "failed_count": 0,
                "assets_sample": [],
                "solution": "—",
                "generated_at": gen_ts
            }, detail_png)
            status = "NO DATA"

        index.append({
            "tag": {"category": cat, "value": val},
            "status": status,
            "paths": {"list": list_png, "detail": detail_png},
        })

        print(f"[{i}/{len(tags)}] ✅ {tag_label} -> {status}")

    # Mantiene el mismo filename del script original (en el root del out-dir)
    try:
        with open(os.path.join(base_out, "index.json"), "w", encoding="utf-8") as f:
            json.dump(index, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    return 0


def _run_tenable_images_per_tag(base_out: str, allowed_tenable: Optional[set[tuple[str, str]]] = None) -> int:
    """
    Ejecuta el módulo 'Tenable_images - funciona.py' pero guardando
    sus 3 imágenes dentro de la carpeta del TAG: base_out/<cat>/<val>/.

    (No cambia el diseño: usa exactamente las mismas funciones render_* del módulo.)
    """
    key = "tenable_images"
    ns = _load_embedded_module(key)

    # Asegura que los outputs generales queden en el mismo root (targets_discovered.json)
    ns["OUTPUT_ROOT"] = base_out
    os.makedirs(base_out, exist_ok=True)

    make_session = ns.get("make_session")
    discover_targets = ns.get("discover_targets")
    process_tag = ns.get("process_tag")
    render_severity_bars = ns.get("render_severity_bars")
    render_top10_list = ns.get("render_top10_list")
    render_spotlight = ns.get("render_spotlight")

    if not (callable(make_session) and callable(discover_targets) and callable(process_tag)
            and callable(render_severity_bars) and callable(render_top10_list) and callable(render_spotlight)):
        print("[ERR] tenable_images: faltan funciones esperadas en el módulo embebido.")
        return 2

    sess = make_session()
    print(f"[INFO] (vm-vulns) Descubriendo tags en categorías: {', '.join(ns.get('WANTED_CATEGORIES', []))} ...")
    targets = discover_targets(sess)
    discovered_count = len(targets)
    filtered_targets = [
        t for t in targets
        if _is_tag_allowed(t.get("tag_category", ""), t.get("tag_value", ""), allowed_tenable)
    ]
    if allowed_tenable is not None:
        if filtered_targets:
            targets = filtered_targets
        else:
            print("[WARN] (vm-vulns) Filtro Tenable sin coincidencias; se procesarán todos los tags descubiertos para no perder 03/04/05.")
        print(f"[INFO] (vm-vulns) Tags existentes={discovered_count} | a procesar={len(targets)}")
    print(f"[INFO] (vm-vulns) Tags descubiertas: {len(targets)}")

    # Guardar targets descubiertos
    try:
        import json as _json
        with open(os.path.join(base_out, "targets_discovered.json"), "w", encoding="utf-8") as f:
            _json.dump(targets, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    sleep_s = ns.get("SLEEP_BETWEEN_EXPORTS_SECONDS", 0) or 0

    for i, t in enumerate(targets, start=1):
        cat = t.get("tag_category", "")
        val = t.get("tag_value", "")
        tag_label = f"{cat} = {val}"
        print(f"[{i}/{len(targets)}] (vm-vulns) Procesando {tag_label}")

        try:
            res = process_tag(sess, t)

            tag_dir = os.path.join(base_out, _safe_fs_name(cat), _safe_fs_name(val))
            os.makedirs(tag_dir, exist_ok=True)

            sev_img = os.path.join(tag_dir, "03_vulns_severity.png")
            top_img = os.path.join(tag_dir, "04_vulns_top10.png")
            sp_img = os.path.join(tag_dir, "05_vulns_spotlight.png")

            render_severity_bars(tag_label, res["severity_counts"], sev_img)
            render_top10_list(tag_label, res["top10_by_vpr"], top_img)

            if res.get("spotlight"):
                render_spotlight(tag_label, res["spotlight"], sp_img)
                print(f"  [OK] total={res['total_vulns']} -> 03/04/05")
            else:
                # Si no hay spotlight, no creamos el archivo
                if os.path.exists(sp_img):
                    try:
                        os.remove(sp_img)
                    except Exception:
                        pass
                print(f"  [OK] total={res['total_vulns']} -> 03/04 (spotlight: none)")

        except Exception as e:
            print(f"  [ERR] {e}")

        if sleep_s and sleep_s > 0:
            time.sleep(float(sleep_s))

    print(f"[DONE] (vm-vulns) Imágenes en: {base_out}")
    return 0


def _identity_counts_from_tenable_one(ns: Dict[str, Any], labels: List[str]) -> Dict[str, Optional[int]]:
    counts: Dict[str, Optional[int]] = {}
    t1_queries = ns.get("T1_QUERIES", {})
    t1_count = ns.get("t1_assets_count")
    if not callable(t1_count):
        raise RuntimeError("Módulo identity no expone t1_assets_count().")
    for label in labels:
        query = t1_queries.get(label)
        print(f"[DEBUG][IDENTITY] KPI='{label}' | modo=Tenable One | query={query}")
        total = int(t1_count(query))
        counts[label] = total
        print(f"[DEBUG][IDENTITY] KPI='{label}' | total={total}")
    return counts


def _identity_ie_single_kpi(ns: Dict[str, Any], label: str) -> Optional[int]:
    wanted = {
        "Dormant Account": "C-SLEEPING-ACCOUNTS",
        "Domain Admin": "C-ADMINCOUNT-ACCOUNT-PROPS",
        "Guest Account": "C-GUEST-ACCOUNT",
    }
    get_profiles = ns.get("get_profiles")
    get_checkers = ns.get("get_checkers")
    count_checker = ns.get("count_deviances_for_checker")
    if not (callable(get_profiles) and callable(get_checkers) and callable(count_checker)):
        raise RuntimeError("Módulo identity no expone funciones IE necesarias.")

    profiles = get_profiles()
    if not profiles:
        raise RuntimeError("Identity Exposure no devolvió profiles.")
    profile_id = str(profiles[0].get("id"))
    codename = wanted.get(label)
    checkers = get_checkers(profile_id)
    codename_to_id = {c.get("codename"): c.get("id") for c in checkers if c.get("codename") and c.get("id")}
    cid = codename_to_id.get(codename)
    print(f"[DEBUG][IDENTITY] KPI='{label}' | modo=Identity Exposure(single) | checker={codename} | checker_id={cid}")
    if not cid:
        return None
    total = int(count_checker(profile_id, cid))
    print(f"[DEBUG][IDENTITY] KPI='{label}' | modo=Identity Exposure(single) | total={total}")
    return total


def _identity_counts_from_ie(ns: Dict[str, Any], labels: List[str]) -> Dict[str, Optional[int]]:
    counts: Dict[str, Optional[int]] = {}
    get_profiles = ns.get("get_profiles")
    get_checkers = ns.get("get_checkers")
    count_checker = ns.get("count_deviances_for_checker")
    if not (callable(get_profiles) and callable(get_checkers) and callable(count_checker)):
        raise RuntimeError("Módulo identity no expone funciones IE necesarias.")

    profiles = get_profiles()
    if not profiles:
        raise RuntimeError("Identity Exposure no devolvió profiles.")
    profile_id = str(profiles[0].get("id"))
    print(f"[DEBUG][IDENTITY] Modo=Identity Exposure | profile_id={profile_id}")

    wanted = {
        "Dormant Account": "C-SLEEPING-ACCOUNTS",
        "Domain Admin": "C-ADMINCOUNT-ACCOUNT-PROPS",
        "Guest Account": "C-GUEST-ACCOUNT",
    }
    checkers = get_checkers(profile_id)
    codename_to_id = {c.get("codename"): c.get("id") for c in checkers if c.get("codename") and c.get("id")}
    for label in labels:
        codename = wanted.get(label)
        cid = codename_to_id.get(codename)
        print(f"[DEBUG][IDENTITY] KPI='{label}' | modo=Identity Exposure | checker={codename} | checker_id={cid}")
        if not cid:
            counts[label] = None
            continue
        total = int(count_checker(profile_id, cid))
        counts[label] = total
        print(f"[DEBUG][IDENTITY] KPI='{label}' | total={total}")
    return counts


def _run_identity_with_debug(ns: Dict[str, Any]) -> int:
    labels = list(ns.get("KPI_LABELS", ["Dormant Account", "Domain Admin", "Guest Account"]))
    make_image = ns.get("make_image")
    if not callable(make_image):
        raise RuntimeError("Módulo identity no expone make_image().")

    mode = os.getenv("IDENTITY_MODE", "auto").strip().lower()
    has_t1 = bool(ns.get("TENABLE_ACCESS_KEY") and ns.get("TENABLE_SECRET_KEY"))
    has_ie = bool(ns.get("IE_API_KEY"))
    print(f"[INFO][IDENTITY] mode={mode} | has_tenable_one_keys={has_t1} | has_ie_api_key={has_ie}")

    counts: Dict[str, Optional[int]]
    if mode == "ie":
        if not has_ie:
            raise RuntimeError("IDENTITY_MODE=ie pero no existe IE_API_KEY.")
        counts = _identity_counts_from_ie(ns, labels)
    elif mode == "t1":
        if not has_t1:
            raise RuntimeError("IDENTITY_MODE=t1 pero faltan llaves TENABLE_ACCESS_KEY/TENABLE_SECRET_KEY.")
        counts = _identity_counts_from_tenable_one(ns, labels)
        dormant = counts.get("Dormant Account")
        if dormant in (None, 0):
            print(f"[WARN][IDENTITY] KPI='Dormant Account' | modo=t1 | total={dormant} | fallback=enabled")
            if has_ie:
                ie_dormant = _identity_ie_single_kpi(ns, "Dormant Account")
                if ie_dormant not in (None, 0):
                    counts["Dormant Account"] = ie_dormant
                    print(f"[WARN][IDENTITY] KPI='Dormant Account' reemplazado por IE | total={ie_dormant}")
                else:
                    print(f"[WARN][IDENTITY] KPI='Dormant Account' IE fallback sin mejora | total_ie={ie_dormant}")
            else:
                print("[WARN][IDENTITY] KPI='Dormant Account' sin IE_API_KEY para fallback.")
    else:
        if has_t1:
            counts = _identity_counts_from_tenable_one(ns, labels)
            dormant = counts.get("Dormant Account")
            if dormant in (None, 0):
                print(f"[WARN][IDENTITY] KPI='Dormant Account' | modo=auto->t1 | total={dormant} | fallback=enabled")
                if has_ie:
                    ie_dormant = _identity_ie_single_kpi(ns, "Dormant Account")
                    if ie_dormant not in (None, 0):
                        counts["Dormant Account"] = ie_dormant
                        print(f"[WARN][IDENTITY] KPI='Dormant Account' reemplazado por IE | total={ie_dormant}")
                    else:
                        print(f"[WARN][IDENTITY] KPI='Dormant Account' IE fallback sin mejora | total_ie={ie_dormant}")
                else:
                    print("[WARN][IDENTITY] KPI='Dormant Account' sin IE_API_KEY para fallback.")
        elif has_ie:
            counts = _identity_counts_from_ie(ns, labels)
        else:
            raise RuntimeError("Sin llaves para Tenable One ni IE_API_KEY para Identity Exposure.")

    if counts.get("Dormant Account") == 0:
        print("[WARN][IDENTITY] Dormant Account quedó en 0; revisar query/endpoint/parsing en tenant.")
    make_image(counts)
    print(f"[INFO][IDENTITY] Counts finales: {counts}")
    print(f"[INFO][IDENTITY] Imagen generada: {ns.get('OUT_FILE')}")
    return 0


def run_all() -> int:
    base_out = _unified_out_dir()
    allowed_tenable = _tenable_allowed_targets_override()
    os.makedirs(base_out, exist_ok=True)

    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        raise SystemExit("❌ Faltan variables de entorno: TENABLE_ACCESS_KEY y TENABLE_SECRET_KEY")

    print("\n===============================")
    print("Tenable Reportes Unificado (AUTO)")
    print("===============================")
    print(f"Salida: {base_out}\n")

    rc_total = 0
    cached_tags = None  # se reutiliza entre módulos CIS (evita llamadas duplicadas a /tags/values)

    # 1) CIS controls (2 imgs + CSV por TAG)
    try:
        print("=== Ejecutando: cis-controls ===")
        ns = _load_embedded_module("cis_audit_charts")

        # Cachea tags una sola vez (los 2 módulos CIS requieren el mismo listado)
        try:
            _s = requests.Session()
            discovered_tags = ns["list_tag_values"](_s)
            cached_tags = _filter_tag_pairs_by_allowed(discovered_tags, allowed_tenable)
            if allowed_tenable is not None:
                print(f"[INFO] (cis-controls) Tags existentes={len(discovered_tags)} | a procesar={len(cached_tags)}")
            if cached_tags:
                ns["list_tag_values"] = (lambda _session, _t=cached_tags: _t)
        except Exception:
            cached_tags = None

        # Unifica salida
        ns["OUT_DIR"] = base_out
        # Reusaremos este export para 2 módulos (cis-controls + cis-host-audits)
        ns["SAVE_RAW_JSONL_GZ"] = True
        ns["RAW_JSONL_GZ_PATH"] = os.path.join(base_out, "compliance_export_all.jsonl.gz")

        rc = _run_module(ns, [])
        if rc != 0:
            rc_total = rc_total or rc
            print(f"[WARN] cis-controls terminó con código {rc}")
    except Exception as e:
        rc_total = rc_total or 1
        print(f"[ERR] cis-controls: {e}")

    # 2) CIS host audits (2 imgs por TAG) -> REUSA el export ya descargado (sin volver a bajar chunks)
    try:
        print("\n=== Ejecutando: cis-host-audits ===")
        ns = _load_embedded_module("controlesCIS")

        # Reutiliza el listado de tags ya consultado en cis-controls (evita otra llamada a /tags/values)
        if cached_tags:
            ns["discover_all_tags"] = (lambda _session, _t=cached_tags: _t)

        dataset_path = os.path.join(base_out, "compliance_export_all.jsonl.gz")

        if os.path.isfile(dataset_path):
            rc = _run_controlesCIS_from_cached_export(
                ns,
                dataset_path,
                base_out,
                rows_to_show=12,
                assets_per_row=3,
                allowed_tenable=allowed_tenable,
            )
        else:
            # Fallback (si cis-controls falló): aquí sí hará export (solo para no dejarte sin imágenes)
            print("[WARN] No existe compliance_export_all.jsonl.gz; se hará export directo (fallback).")
            rc = _run_module(ns, ["--out-dir", base_out])

        if rc != 0:
            rc_total = rc_total or rc
            print(f"[WARN] cis-host-audits terminó con código {rc}")
    except Exception as e:
        rc_total = rc_total or 1
        print(f"[ERR] cis-host-audits: {e}")

# 3) VM vulns (severidad + top10 + spotlight) -> guardando dentro de carpeta del TAG
    try:
        print("\n=== Ejecutando: vm-vulns ===")
        rc = _run_tenable_images_per_tag(base_out, allowed_tenable=allowed_tenable)
        if rc != 0:
            rc_total = rc_total or rc
            print(f"[WARN] vm-vulns terminó con código {rc}")
    except Exception as e:
        rc_total = rc_total or 1
        print(f"[ERR] vm-vulns: {e}")

    # 4) Identity donuts (1 imagen) -> la copiamos dentro de CADA carpeta de TAG
    identity_path = os.path.join(base_out, "identity_exposure_donuts_4k.png")
    try:
        print("\n=== Ejecutando: identity ===")
        ns = _load_embedded_module("tenable_identity")

        # Unifica salida
        ns["OUT_FILE"] = identity_path

        rc = _run_identity_with_debug(ns)
        if rc != 0:
            rc_total = rc_total or rc
            print(f"[WARN] identity terminó con código {rc}")
    except Exception as e:
        rc_total = rc_total or 1
        print(f"[ERR] identity: {e}")

    # Copiar identity a carpetas de tag permitidas (si existe)
    try:
        if os.path.isfile(identity_path):
            for tag_dir in _iter_tag_dirs(base_out):
                rel = os.path.relpath(tag_dir, base_out)
                parts = rel.split(os.sep)
                if len(parts) >= 2 and not _is_tag_allowed(parts[0], parts[1], allowed_tenable):
                    continue
                dst = os.path.join(tag_dir, os.path.basename(identity_path))
                try:
                    shutil.copy2(identity_path, dst)
                except Exception:
                    pass
            print("\n[OK] identity_exposure_donuts_4k.png copiada a carpetas de TAG permitidas.")
    except Exception:
        pass

    print("\n✅ Listo.")
    print(f"✅ Carpeta final: {base_out}")
    return rc_total


def tenable_main() -> int:
    # Ignoramos cualquier argumento: el usuario pidió ejecución 100% automática.
    return run_all()


if __name__ == "__main__":
    raise SystemExit(main())
