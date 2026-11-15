#!/usr/bin/env python3
"""Servicio mínimo de credenciales: el digest se guarda truncado a cuatro hex.

HUELLA-OFFREP-009-APP-20261115

Qué modela
----------
Un servicio con dos cuentas y claves largas —ninguna está en ningún diccionario—. Al
registrar, se guarda `md5(clave)[:4]`: cuatro caracteres hexadecimales, dieciséis bits.
Al autenticar se compara el digest calculado con el guardado.

La truncación es la decisión que nadie discutió: cuatro hex son **65 536 valores posibles**,
así que "alguna clave que dé este digest" deja de ser una búsqueda y pasa a ser una
enumeración.

`respaldo()` modela el volcado de la tabla de credenciales, que es como un atacante obtiene
el par (sal, digest). La sal **no es secreta**: vive junto al digest en la misma tabla.

    python3 app_vulnerable.py --usuario ana --clave 'Tr0ub4dor&3-ana'

Códigos
-------
0   la operación se atendió
1   la autenticación fue rechazada
20  argumentos incompatibles
"""

from __future__ import annotations

import argparse
import hashlib
import sys

ALMACEN: dict[str, tuple[str, str]] = {}  # usuario -> (sal, digest)


def _md5(texto: str) -> str:
    return hashlib.md5(texto.encode()).hexdigest()


def registrar(usuario: str, clave: str, estricto: bool = True) -> str:
    """Guarda la credencial y devuelve el digest almacenado."""
    digest = _md5(clave)[:4]
    ALMACEN[usuario] = ("", digest)
    return digest


def autenticar(usuario: str, clave: str, estricto: bool = True) -> bool:
    if usuario not in ALMACEN:
        return False
    _sal, digest = ALMACEN[usuario]
    return _md5(clave)[:4] == digest


def respaldo() -> dict[str, dict[str, str]]:
    """El volcado de la tabla, tal como lo leería quien lo obtiene."""
    return {usuario: {"sal": sal, "digest": digest} for usuario, (sal, digest) in ALMACEN.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Credenciales con digest truncado a 4 hex.")
    parser.add_argument("--usuario", required=True)
    parser.add_argument("--clave", required=True)
    parser.add_argument("--registrar", action="store_true", help="registra en vez de autenticar")
    args = parser.parse_args(argv)

    if args.registrar:
        print(registrar(args.usuario, args.clave))
        return 0
    if autenticar(args.usuario, args.clave):
        print("ADMITIDA")
        return 0
    print(f"RECHAZADO: clave incorrecta para {args.usuario}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
