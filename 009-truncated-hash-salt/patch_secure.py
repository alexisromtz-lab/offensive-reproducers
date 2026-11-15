#!/usr/bin/env python3
"""Las mismas credenciales, en dos versiones.

HUELLA-OFFREP-009-PARCHE-20261115

    python3 patch_secure.py --registrar --usuario ana --clave ...   # canonico
    python3 patch_secure.py --naive --registrar ...                 # el que cierra el caso reportado

Canonico
--------
La entropía de un digest es su longitud, no su sal: `pbkdf2_hmac` con sal por cuenta y
digest completo de 256 bits. Enumerar el espacio deja de ser una opción —hay 2^256
valores— y la comparación es de tiempo constante. Se usa PBKDF2 y no `scrypt` porque
`scrypt` no está en toda biblioteca estándar (medido: ausente en el Python de macOS que
acompaña al sistema) y esta cápsula no instala nada.

Ingenuo
-------
Arregla **el caso que se reportó**: «las claves se guardan sin sal, una tabla precompartida
las abre todas». Añade sal por cuenta… y **conserva la truncación a cuatro hex**. La sal
hace su trabajo: la tabla precompartida sobre claves ya no sirve, hay que reconstruirla por
cuenta. Lo que no hace —no puede hacerlo— es devolver la entropía que la truncación se
llevó: 65 536 digests posibles se enumeran en un tercio de segundo, y la sal necesaria para
ello viaja en el mismo volcado que el digest.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import sys

ALMACEN: dict[str, tuple[str, str]] = {}  # usuario -> (sal, digest)

ITERACIONES_CANONICO = 120_000  # coste del canónico: se mide el criterio, no el récord


def _md5(texto: str) -> str:
    return hashlib.md5(texto.encode()).hexdigest()


def _sal_ingenuo(usuario: str) -> str:
    return _md5("sal:" + usuario)[:8]


def _sal_canonico(usuario: str) -> str:
    return _md5("sal:" + usuario)[:16]


def _digest_canonico(sal: str, clave: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", clave.encode(), sal.encode(), ITERACIONES_CANONICO).hex()


def _registrar_ingenuo(usuario: str, clave: str) -> str:
    sal = _sal_ingenuo(usuario)
    digest = _md5(sal + clave)[:4]
    ALMACEN[usuario] = (sal, digest)
    return digest


def _autenticar_ingenuo(usuario: str, clave: str) -> bool:
    if usuario not in ALMACEN:
        return False
    sal, digest = ALMACEN[usuario]
    return _md5(sal + clave)[:4] == digest


def _registrar_canonico(usuario: str, clave: str) -> str:
    sal = _sal_canonico(usuario)
    digest = _digest_canonico(sal, clave)
    ALMACEN[usuario] = (sal, digest)
    return digest


def _autenticar_canonico(usuario: str, clave: str) -> bool:
    if usuario not in ALMACEN:
        return False
    sal, digest = ALMACEN[usuario]
    return hmac.compare_digest(_digest_canonico(sal, clave), digest)


def registrar(usuario: str, clave: str, estricto: bool = True) -> str:
    if estricto:
        return _registrar_canonico(usuario, clave)
    return _registrar_ingenuo(usuario, clave)


def autenticar(usuario: str, clave: str, estricto: bool = True) -> bool:
    if estricto:
        return _autenticar_canonico(usuario, clave)
    return _autenticar_ingenuo(usuario, clave)


def respaldo() -> dict[str, dict[str, str]]:
    """El volcado de la tabla, tal como lo leería quien lo obtiene."""
    return {usuario: {"sal": sal, "digest": digest} for usuario, (sal, digest) in ALMACEN.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Credenciales con sal y digest completo.")
    parser.add_argument("--usuario", required=True)
    parser.add_argument("--clave", required=True)
    parser.add_argument("--registrar", action="store_true", help="registra en vez de autenticar")
    parser.add_argument("--naive", action="store_true", help="modo ingenuo")
    args = parser.parse_args(argv)

    estricto = not args.naive
    if args.registrar:
        print(registrar(args.usuario, args.clave, estricto=estricto))
        return 0
    if autenticar(args.usuario, args.clave, estricto=estricto):
        print("ADMITIDA")
        return 0
    print(f"RECHAZADO: clave incorrecta para {args.usuario}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
