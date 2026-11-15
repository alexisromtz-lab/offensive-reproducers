#!/usr/bin/env python3
"""Las mismas cabeceras, en dos versiones.

HUELLA-OFFREP-007-PARCHE-20261115

    python3 patch_secure.py --origen https://app.tiendaplatino.com.mx   # canonico
    python3 patch_secure.py --naive --origen ...                        # el que cierra el caso reportado

Canonico
--------
Lista blanca de origenes **completos** y comparacion exacta. Un origen es un valor
finito —esquema, host y puerto— y se compara entero o no se compara.

Ingenuo
-------
Arregla **el caso que se reporto**: deja de reflejar cualquier origen y comprueba que el
dominio propio aparezca en la cadena. El informe decia «refleja origenes ajenos», y con
`in` un origen ajeno que *mencione* el dominio propio pasa: los subdominios del atacante
no existen, pero `https://app.tiendaplatino.com.mx.evil.example` tampoco es nuestro y
contiene la cadena. Comparar por subcadena confunde "habla de mi dominio" con "es mi
dominio".
"""

from __future__ import annotations

import argparse
import json

ORIGENES_PERMITIDOS = frozenset({"https://app.tiendaplatino.com.mx"})
MARCA_DOMINIO = "tiendaplatino.com.mx"


def _cabeceras_ingenuo(origen: str, autenticado: bool) -> dict[str, str]:
    permitido = MARCA_DOMINIO in origen
    return {
        "Access-Control-Allow-Origin": origen if permitido else "https://app.tiendaplatino.com.mx",
        "Access-Control-Allow-Credentials": "true" if (permitido and autenticado) else "false",
        "Vary": "Origin",
    }


def _cabeceras_canonico(origen: str, autenticado: bool) -> dict[str, str]:
    permitido = origen in ORIGENES_PERMITIDOS
    return {
        "Access-Control-Allow-Origin": origen if permitido else "https://app.tiendaplatino.com.mx",
        "Access-Control-Allow-Credentials": "true" if (permitido and autenticado) else "false",
        "Vary": "Origin",
    }


def cabeceras(origen: str, autenticado: bool = True, estricto: bool = True) -> dict[str, str]:
    if estricto:
        return _cabeceras_canonico(origen, autenticado)
    return _cabeceras_ingenuo(origen, autenticado)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cabeceras CORS (parcheadas).")
    parser.add_argument("--origen", default="")
    parser.add_argument("--naive", action="store_true", help="modo ingenuo")
    args = parser.parse_args(argv)
    print(json.dumps(cabeceras(args.origen, estricto=not args.naive), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
