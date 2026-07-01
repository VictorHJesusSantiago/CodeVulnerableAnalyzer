"""
Detecção de segredos em conteúdo não-textual: binários (via extração de
strings ASCII/UTF-16, como o comando Unix `strings`), imagens JPEG (parser
EXIF/TIFF mínimo via `struct`, stdlib) e PDFs (extração best-effort de texto
não comprimido). Também inclui parsing dedicado de arquivos .env.

Escopo declarado: o parser de PDF NÃO decodifica streams comprimidos
(FlateDecode/zlib) fora do necessário — extrai apenas texto literal presente
em claro no arquivo (comum em PDFs gerados sem compressão ou com metadados
em claro). PDFs totalmente comprimidos exigiriam um parser de objetos +
inflate completo, fora do escopo aqui (mas o zlib da stdlib é usado quando
um stream FlateDecode é encontrado, então há suporte parcial real).
"""
from __future__ import annotations
import re
import struct
import zlib
from pathlib import Path
from typing import List, Optional, Tuple

from analyzer.secrets_providers import classify_secret
from analyzer.entropy import scan_entropy


# ════════════════════════════════════════════════════════════════════════════
#  Extração de strings de binários (equivalente a `strings`)
# ════════════════════════════════════════════════════════════════════════════

_MIN_STRING_LEN = 6
_ASCII_RUN_RE = re.compile(rb'[\x20-\x7e]{%d,}' % _MIN_STRING_LEN)


def extract_strings(data: bytes, min_len: int = _MIN_STRING_LEN) -> List[str]:
    """Extrai sequências de bytes ASCII imprimíveis (>= min_len), similar ao
    comando `strings`. Também tenta UTF-16LE (comum em binários Windows)."""
    results = []
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
    for m in pattern.finditer(data):
        try:
            results.append(m.group(0).decode("ascii"))
        except UnicodeDecodeError:
            continue

    # UTF-16LE: bytes intercalados com \x00
    utf16_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_len)
    for m in utf16_pattern.finditer(data):
        try:
            results.append(m.group(0).decode("utf-16le"))
        except UnicodeDecodeError:
            continue

    return results


def scan_binary_for_secrets(file_path: str, data: bytes) -> List[dict]:
    """Extrai strings do binário e roda a classificação de provedores +
    entropia sobre cada string encontrada."""
    findings = []
    strings = extract_strings(data)
    joined = "\n".join(strings)

    for provider, secret_type, matched, revoke_url in classify_secret(joined):
        findings.append({
            "file_path": file_path, "source": "binary-strings",
            "provider": provider, "secret_type": secret_type,
            "matched": matched[:60], "revoke_url": revoke_url,
        })

    for entry in scan_entropy(file_path, joined, threshold=4.2):
        findings.append({
            "file_path": file_path, "source": "binary-strings-entropy",
            "provider": "Desconhecido", "secret_type": "Alta entropia",
            "matched": entry.secret_value[:60], "revoke_url": "N/A",
        })
    return findings


# ════════════════════════════════════════════════════════════════════════════
#  EXIF (parser TIFF/IFD mínimo sobre APP1 de JPEG)
# ════════════════════════════════════════════════════════════════════════════

_EXIF_TAG_NAMES = {
    0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model",
    0x0131: "Software", 0x8298: "Copyright", 0x9286: "UserComment",
    0x013B: "Artist", 0x8769: "ExifIFDPointer",
}


def _read_ifd(data: bytes, ifd_offset: int, endian: str) -> List[Tuple[int, int, int, bytes]]:
    """Lê um IFD (Image File Directory) TIFF e retorna [(tag, type, count, raw_value), ...]."""
    fmt = "<H" if endian == "<" else ">H"
    if ifd_offset + 2 > len(data):
        return []
    num_entries = struct.unpack_from(fmt, data, ifd_offset)[0]
    entries = []
    entry_fmt = f"{endian}HHI4s"
    for i in range(num_entries):
        entry_offset = ifd_offset + 2 + i * 12
        if entry_offset + 12 > len(data):
            break
        tag, typ, count, value_bytes = struct.unpack_from(entry_fmt, data, entry_offset)
        entries.append((tag, typ, count, value_bytes))
    return entries


def extract_exif_strings(jpeg_data: bytes) -> List[str]:
    """Extrai valores de string de tags EXIF de um JPEG (parser TIFF/IFD real,
    via struct — sem dependência de Pillow/exifread)."""
    results: List[str] = []
    if not jpeg_data.startswith(b"\xff\xd8"):
        return results

    offset = 2
    app1_data: Optional[bytes] = None
    while offset < len(jpeg_data) - 4:
        marker = jpeg_data[offset:offset + 2]
        if marker[0:1] != b"\xff":
            break
        if marker == b"\xff\xe1":  # APP1
            seg_len = struct.unpack(">H", jpeg_data[offset + 2:offset + 4])[0]
            segment = jpeg_data[offset + 4: offset + 2 + seg_len]
            if segment[:6] == b"Exif\x00\x00":
                app1_data = segment[6:]
            break
        elif marker == b"\xff\xd9":  # EOI
            break
        else:
            if len(jpeg_data) < offset + 4:
                break
            seg_len = struct.unpack(">H", jpeg_data[offset + 2:offset + 4])[0]
            offset += 2 + seg_len

    if app1_data is None or len(app1_data) < 8:
        return results

    endian = "<" if app1_data[0:2] == b"II" else ">"
    ifd0_offset = struct.unpack(f"{endian}I", app1_data[4:8])[0]
    entries = _read_ifd(app1_data, ifd0_offset, endian)

    for tag, typ, count, raw in entries:
        if tag not in _EXIF_TAG_NAMES:
            continue
        # Tipo 2 = ASCII; se count <= 4, o valor está inline em raw; senão é um offset
        if typ == 2:
            if count <= 4:
                value = raw[:count].rstrip(b"\x00")
            else:
                value_offset = struct.unpack(f"{endian}I", raw)[0]
                value = app1_data[value_offset:value_offset + count].rstrip(b"\x00")
            try:
                results.append(f"{_EXIF_TAG_NAMES[tag]}={value.decode('ascii', errors='replace')}")
            except Exception:
                pass
    return results


def scan_image_exif_for_secrets(file_path: str, data: bytes) -> List[dict]:
    strings = extract_exif_strings(data)
    joined = "\n".join(strings)
    findings = []
    for provider, secret_type, matched, revoke_url in classify_secret(joined):
        findings.append({
            "file_path": file_path, "source": "exif",
            "provider": provider, "secret_type": secret_type,
            "matched": matched[:60], "revoke_url": revoke_url,
        })
    return findings


# ════════════════════════════════════════════════════════════════════════════
#  PDF (extração best-effort de texto, incl. streams FlateDecode)
# ════════════════════════════════════════════════════════════════════════════

_PDF_STREAM_RE = re.compile(rb'stream\r?\n(.*?)endstream', re.DOTALL)
_PDF_TEXT_LITERAL_RE = re.compile(rb'\((?:[^()\\]|\\.)*\)')


def extract_pdf_text(data: bytes) -> str:
    """Extrai texto de um PDF: literais de texto em claro '(...)' fora de
    streams, e o conteúdo de streams FlateDecode (descomprimidos via zlib)."""
    texts: List[str] = []

    for lit in _PDF_TEXT_LITERAL_RE.finditer(data):
        raw = lit.group(0)[1:-1]
        try:
            texts.append(raw.decode("latin-1", errors="replace"))
        except Exception:
            pass

    for stream_match in _PDF_STREAM_RE.finditer(data):
        raw_stream = stream_match.group(1)
        try:
            decompressed = zlib.decompress(raw_stream)
            for lit in _PDF_TEXT_LITERAL_RE.finditer(decompressed):
                raw = lit.group(0)[1:-1]
                texts.append(raw.decode("latin-1", errors="replace"))
            # Também roda extração de strings puras no stream descomprimido
            texts.append(decompressed.decode("latin-1", errors="replace"))
        except zlib.error:
            continue

    return "\n".join(texts)


def scan_pdf_for_secrets(file_path: str, data: bytes) -> List[dict]:
    text = extract_pdf_text(data)
    findings = []
    for provider, secret_type, matched, revoke_url in classify_secret(text):
        findings.append({
            "file_path": file_path, "source": "pdf",
            "provider": provider, "secret_type": secret_type,
            "matched": matched[:60], "revoke_url": revoke_url,
        })
    return findings


# ════════════════════════════════════════════════════════════════════════════
#  .env (parsing dedicado KEY=VALUE)
# ════════════════════════════════════════════════════════════════════════════

_ENV_LINE_RE = re.compile(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$')


def parse_env_file(content: str) -> List[Tuple[int, str, str]]:
    """Retorna [(line_number, key, value), ...] de um arquivo .env."""
    results = []
    for i, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _ENV_LINE_RE.match(line)
        if m:
            key, value = m.groups()
            value = value.strip().strip('"').strip("'")
            results.append((i, key, value))
    return results


def scan_env_for_secrets(file_path: str, content: str) -> List[dict]:
    findings = []
    for line_number, key, value in parse_env_file(content):
        if not value:
            continue
        for provider, secret_type, matched, revoke_url in classify_secret(f"{key}={value}"):
            findings.append({
                "file_path": file_path, "source": "env", "line_number": line_number,
                "provider": provider, "secret_type": secret_type,
                "matched": matched[:60], "revoke_url": revoke_url,
            })
        if not findings or findings[-1].get("line_number") != line_number:
            # Heurística adicional: chave com nome sensível + valor não trivial
            if re.search(r'(?i)(?:secret|password|token|key|credential)', key) and len(value) >= 8:
                findings.append({
                    "file_path": file_path, "source": "env", "line_number": line_number,
                    "provider": "Genérico", "secret_type": f"Variável sensível '{key}'",
                    "matched": value[:60], "revoke_url": "N/A",
                })
    return findings


# ════════════════════════════════════════════════════════════════════════════
#  Orquestração
# ════════════════════════════════════════════════════════════════════════════

def scan_non_text_file(file_path: str) -> List[dict]:
    """Detecta o tipo do arquivo pelos magic bytes/extensão e roda o scanner
    apropriado. Retorna lista de achados em formato dict uniforme."""
    path = Path(file_path)
    ext = path.suffix.lower()
    try:
        data = path.read_bytes()
    except (OSError, PermissionError):
        return []

    if ext in (".env",) or path.name.startswith(".env"):
        try:
            return scan_env_for_secrets(file_path, data.decode("utf-8", errors="replace"))
        except Exception:
            return []
    if ext in (".jpg", ".jpeg"):
        return scan_image_exif_for_secrets(file_path, data)
    if ext == ".pdf":
        return scan_pdf_for_secrets(file_path, data)
    if ext in (".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".obj"):
        return scan_binary_for_secrets(file_path, data)
    return []
