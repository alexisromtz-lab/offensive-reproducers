#!/usr/bin/env python3
"""Extractor de archivos: confía en los nombres que trae el archivo.

HUELLA-OFFREP-005-APP-20261113

Qué modela
----------
Un servicio que recibe un `.tar` y lo descomprime en un directorio de trabajo. El nombre de
cada miembro lo escribe quien construyó el archivo, así que un nombre es una **ruta**, y una
ruta puede salir del directorio. `extractall` no pregunta: escribe donde el nombre diga.

    python3 app_vulnerable.py --datos archivo.tar --destino salida

Códigos
-------
0   el archivo se extrajo
1   el archivo se rechazó
20  argumentos incompatibles

Sin red. El disco sólo se toca bajo el directorio que el usuario declare.
"""

from __future__ import annotations

import argparse
import inspect
import io
import sys
import tarfile
from pathlib import Path


class ArchivoRechazado(Exception):
    """El archivo no se puede extraer en ese destino."""


def _extraer_confiando(tar: tarfile.TarFile, destino: Path) -> None:
    """Extrae sin filtro. En Python 3.12+ hay que pedirlo por su nombre."""
    opciones = {}
    if "filter" in inspect.signature(tarfile.TarFile.extractall).parameters:
        opciones["filter"] = "fully_trusted"
    tar.extractall(destino, **opciones)


def extraer(datos: bytes, destino: Path | str, estricto: bool = True) -> list[str]:
    """Extrae el archivo en `destino` y devuelve los nombres escritos, tal como venían."""
    destino = Path(destino)
    destino.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(datos), mode="r:*") as tar:
        _extraer_confiando(tar, destino)
        return [miembro.name for miembro in tar.getmembers()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extractor de archivos tar.")
    parser.add_argument("--datos", required=False, help="archivo .tar a extraer")
    parser.add_argument("--destino", required=False, help="directorio de destino")
    args = parser.parse_args(argv)

    if not args.datos or not args.destino:
        parser.error("hacen falta --datos y --destino")
        return 20

    try:
        escritos = extraer(Path(args.datos).read_bytes(), Path(args.destino))
    except (OSError, tarfile.TarError, ArchivoRechazado) as exc:
        print(f"RECHAZADO: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    for nombre in escritos:
        print(nombre)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
