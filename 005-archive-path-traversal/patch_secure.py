#!/usr/bin/env python3
"""Parche del extractor, en dos versiones.

HUELLA-OFFREP-005-PARCHE-20261113

    python3 patch_secure.py              # canónico
    python3 patch_secure.py --naive      # el que cierra el caso reportado

El canónico decide sobre la **ruta resuelta** y antes de escribir un solo byte:

1. valida todos los miembros primero; si uno falla, no se extrae ninguno;
2. rechaza nombres absolutos y nombres con byte nulo;
3. sólo admite ficheros regulares y directorios: ni enlaces, ni dispositivos, ni FIFOs;
4. compara por **componentes** con `os.path.commonpath` sobre `realpath`, no por prefijo de
   cadena — `/base/lab` y `/base/lab_eve` comparten prefijo y no comparten directorio;
5. se niega a pisar un archivo que ya existe: la extracción no es una escritura silenciosa.

El ingenuo arregla **el nombre que se reportó**: comprueba que la ruta absoluta del miembro
empiece por la del destino. Esa comprobación es de texto, así que cae ante un directorio
hermano con el mismo prefijo, ante un enlace simbólico —cuyo nombre no tiene nada raro— y
ante un archivo que ya existía.
"""

from __future__ import annotations

import argparse
import inspect
import io
import os
import sys
import tarfile
from pathlib import Path


class ArchivoRechazado(Exception):
    """El archivo no se puede extraer en ese destino."""


def _extraer_confiando(tar: tarfile.TarFile, destino: Path) -> None:
    opciones = {}
    if "filter" in inspect.signature(tarfile.TarFile.extractall).parameters:
        opciones["filter"] = "fully_trusted"
    tar.extractall(destino, **opciones)


def _dentro(raiz: str, objetivo: str) -> bool:
    """¿`objetivo` está dentro de `raiz`? Por componentes, no por prefijo de cadena."""
    try:
        return os.path.commonpath([raiz, objetivo]) == raiz
    except ValueError:  # rutas en unidades distintas o mezcla absoluto/relativo
        return False


def _validar(miembro: tarfile.TarInfo, raiz: str) -> None:
    nombre = miembro.name
    if "\x00" in nombre:
        raise ArchivoRechazado(f"nombre con byte nulo: {nombre!r}")
    if os.path.isabs(nombre):
        raise ArchivoRechazado(f"nombre absoluto: {nombre!r}")
    if miembro.issym() or miembro.islnk():
        raise ArchivoRechazado(f"enlace no admitido: {nombre!r}")
    if not (miembro.isfile() or miembro.isdir()):
        raise ArchivoRechazado(f"tipo no admitido en {nombre!r}")
    objetivo = os.path.realpath(os.path.join(raiz, nombre))
    if not _dentro(raiz, objetivo):
        raise ArchivoRechazado(f"la ruta sale del destino: {nombre!r}")
    if os.path.lexists(objetivo):
        raise ArchivoRechazado(f"ya existe y no se pisa: {nombre!r}")


def extraer(datos: bytes, destino: Path | str, estricto: bool = True) -> list[str]:
    destino = Path(destino)
    destino.mkdir(parents=True, exist_ok=True)
    raiz = os.path.realpath(destino)
    nombres: list[str] = []

    with tarfile.open(fileobj=io.BytesIO(datos), mode="r:*") as tar:
        miembros = tar.getmembers()

        if not estricto:
            for miembro in miembros:
                objetivo = os.path.abspath(os.path.join(destino, miembro.name))
                if not objetivo.startswith(os.path.abspath(destino)):
                    raise ArchivoRechazado(f"la ruta sale del destino: {miembro.name!r}")
            _extraer_confiando(tar, destino)
            return [miembro.name for miembro in miembros]

        # Se valida entero antes de escribir: un archivo con un miembro hostil no deja
        # medio árbol extraído en el destino.
        for miembro in miembros:
            _validar(miembro, raiz)
        for miembro in miembros:
            tar.extract(miembro, destino, set_attrs=False)
            nombres.append(miembro.name)
    return nombres


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extractor de archivos tar con validacion.")
    parser.add_argument("--naive", action="store_true", help="modo ingenuo")
    parser.add_argument("--datos", required=False)
    parser.add_argument("--destino", required=False)
    args = parser.parse_args(argv)
    estricto = not args.naive

    if not args.datos or not args.destino:
        parser.error("hacen falta --datos y --destino")
        return 20

    try:
        escritos = extraer(Path(args.datos).read_bytes(), Path(args.destino), estricto=estricto)
    except (OSError, tarfile.TarError, ArchivoRechazado) as exc:
        print(f"RECHAZADO: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    for nombre in escritos:
        print(nombre)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
