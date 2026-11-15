#!/usr/bin/env python3
"""Sujeto vulnerable: la API devuelve CORS reflejando el origen que le llega.

HUELLA-OFFREP-007-APP-20261115

Una API que autentica por cookie no puede decir "cualquier origen puede leer esto con
credenciales": el navegador obedece, y el sitio del atacante lee la respuesta ajena.

El sujeto no tiene servidor: es una funcion pura de cabeceras. Asi el fallo es el
criterio, no el transporte, y la corrida es determinista sin red.
"""

from __future__ import annotations

import argparse
import json

ORIGEN_TRUSTADO = "https://app.tiendaplatino.com.mx"


def cabeceras(origen: str, autenticado: bool = True, **_ignorados: object) -> dict[str, str]:
    """Cabeceras CORS para `origen`. Refleja lo que llega, sin mirar quien es."""
    return {
        "Access-Control-Allow-Origin": origen or "*",
        "Access-Control-Allow-Credentials": "true" if autenticado else "false",
        "Vary": "Origin",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cabeceras CORS (vulnerable).")
    parser.add_argument("--origen", default="")
    args = parser.parse_args(argv)
    print(json.dumps(cabeceras(args.origen), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
