import hashlib
import io
import json
import struct
import sys
import zipfile
import zlib
from collections import Counter
from pathlib import Path
from PIL import Image

WORKSHOP_ID = "2850199955"
MAX_ENTRY_BYTES = 512 * 1024 * 1024

def parse_tmod(path):
    source = Path(path).read_bytes()
    if source[:4] != b"TMOD":
        raise ValueError("Cabecalho TMOD invalido: " + source[:32].hex(" "))
    version_length = source[4]
    if not 1 <= version_length <= 40:
        raise ValueError("Comprimento da versao tModLoader invalido")
    tml_version = source[5:5+version_length].decode("ascii")
    position = 5 + version_length + 280

    def read_string():
        nonlocal position
        length = shift = 0
        for _ in range(5):
            char = source[position]
            position += 1
            length |= (char & 127) << shift
            if char < 128:
                break
            shift += 7
        else:
            raise ValueError("Comprimento de string incorreto")
        if length > 100000 or position + length > len(source):
            raise ValueError("String fora dos limites")
        value = source[position:position + length].decode("utf-8")
        position += length
        return value

    name = read_string()
    version = read_string()
    file_count, = struct.unpack_from("<I", source, position)
    position += 4
    if file_count < 1 or file_count > 1000000:
        raise ValueError("Quantidade de arquivos invalida")
    entries = []
    for _ in range(file_count):
        filename = read_string()
        unpacked_size, compressed_size = struct.unpack_from("<II", source, position)
        position += 8
        entries.append((filename, unpacked_size, compressed_size))
    if position + sum(packed for _, _, packed in entries) != len(source):
        raise ValueError("Indice TMOD nao confere")
    return source, position, tml_version, name, version, entries

def extract(path, dest):
    source, position, tml, name, version, entries = parse_tmod(path)
    out = Path(dest)
    bin_dir = out / "Binarios"
    bin_dir.mkdir(parents=True, exist_ok=True)
    counters = Counter()
    suffixes = Counter()
    bad_images = []
    hashes = {}
    source_files = []
    with zipfile.ZipFile(out / "Texturas_PNG.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=6) as png_zip, \
         zipfile.ZipFile(out / "Recursos_Extras.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=6) as extras_zip, \
         zipfile.ZipFile(out / "Fontes_Inclusas.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=6) as source_zip:
        for filename, raw_size, packed_size in entries:
            if raw_size > MAX_ENTRY_BYTES:
                raise ValueError("Recurso muito grande: " + filename)
            packed = source[position:position + packed_size]
            position += packed_size
            raw = zlib.decompress(packed, -15) if raw_size != packed_size else packed
            if len(raw) != raw_size:
                raise ValueError("Comprimento incorreto: " + filename)
            path_entry = Path(filename.replace("\\", "/"))
            if path_entry.is_absolute() or ".." in path_entry.parts:
                raise ValueError("Nome de recurso inseguro: " + filename)
            ext = path_entry.suffix.lower()
            suffixes[ext or "sem_extensao"] += 1
            if ext == ".rawimg":
                try:
                    if len(raw) < 12:
                        raise ValueError("Cabecalho rawimg curto")
                    fmt, w, h = struct.unpack_from("<III", raw)
                    if fmt != 1 or not 0 < w <= 16384 or not 0 < h <= 16384 or len(raw) != 12 + w * h * 4:
                        raise ValueError(f"Formato {fmt}; dimensoes {w}x{h}; bytes {len(raw)}")
                    image = Image.frombytes("RGBA", (w, h), raw[12:])
                    output = io.BytesIO()
                    image.save(output, "PNG")
                    png_zip.writestr(str(path_entry.with_suffix(".png")), output.getvalue())
                    counters["png"] += 1
                except Exception as ex:
                    bad_images.append({"file": filename, "error": str(ex)})
                    extras_zip.writestr(str(path_entry), raw)
                    counters["extra"] += 1
            elif ext in (".png", ".jpg", ".jpeg", ".webp", ".gif"):
                png_zip.writestr(str(path_entry), raw)
                counters["png"] += 1
            elif ext in (".dll", ".pdb") and (path_entry.parent == Path(".") or path_entry.name.lower().startswith(name.lower())):
                (bin_dir / path_entry.name).write_bytes(raw)
                hashes[path_entry.name] = hashlib.sha256(raw).hexdigest()
                counters["binary"] += 1
            else:
                extras_zip.writestr(str(path_entry), raw)
                counters["extra"] += 1
                if filename.lower().endswith((".cs", ".cs.bak", ".csproj", ".sln", ".slnx")):
                    source_zip.writestr(str(path_entry), raw)
                    source_files.append(filename)
    dll = bin_dir / (name + ".dll")
    if not dll.exists():
        dlls = list(bin_dir.glob("*.dll"))
        if len(dlls) != 1:
            raise ValueError("DLL principal nao identificada: " + str(dlls))
        dll = dlls[0]
    report = {
        "workshop_id": WORKSHOP_ID,
        "nome_interno": name,
        "versao_mod": version,
        "versao_tmodloader": tml,
        "tmod_sha256": hashlib.sha256(source).hexdigest(),
        "total_arquivos_tmod": len(entries),
        "texturas_png": counters["png"],
        "recursos_extras": counters["extra"],
        "binarios_extraidos": counters["binary"],
        "fontes_embutidas": len(source_files),
        "arquivos_fonte_embutidos": source_files,
        "imagens_nao_convertidas": bad_images,
        "tipos_de_arquivo": dict(suffixes),
        "sha256_binarios": hashes,
        "dll_principal": str(dll),
    }
    (out / "Relatorio_Extracao.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k not in ("arquivos_fonte_embutidos", "tipos_de_arquivo", "imagens_nao_convertidas")}, ensure_ascii=False, indent=2))
    print("Falhas na conversao de imagens:", len(bad_images))
    return dll

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Uso: python3 extract_tmod.py caminho/mod.tmod saida/")
    extract(sys.argv[1], sys.argv[2])
