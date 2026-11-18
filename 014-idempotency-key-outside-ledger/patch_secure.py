#!/usr/bin/env python3
"""Parche canónico del libro de cobros: la clave se guarda **en el asiento**, y el asiento es el
candado.

HUELLA-OFFREP-014-PARCHE-20261118

Qué cambia
----------
El registro de claves deja de ser un objeto aparte que cada puerta puede ignorar. La comprobación
vive en el único punto por el que pasan las tres puertas --`_asentar`--, así que una puerta nueva
nace cerrada: no hay forma de escribir en el libro sin que el libro mire la clave.

    python3 exploit_poc.py --app patch_secure.py            # RC 1
    python3 exploit_poc.py --app patch_secure.py --naive    # RC 0, la clase sigue abierta
"""
from __future__ import annotations

import argparse
from typing import Any

MONTO_AUTORIZADO = 10.0

LIBRO: list[dict[str, Any]] = []
CLAVES: set[str] = set()


class Rechazo(ValueError):
    """Rechazo declarado: el libro no se tocó."""


def validar(clave: str, monto: float) -> float:
    if not clave:
        raise Rechazo("la clave de idempotencia no puede venir vacia")
    if monto <= 0:
        raise Rechazo(f"monto no positivo: {monto!r}")
    return monto


def _ya_asentada(clave: str) -> bool:
    """La pregunta se hace al libro, no a un registro paralelo que puede divergir de él."""
    return any(asiento["clave"] == clave for asiento in LIBRO)


def _asentar(clave: str, monto: float, puerta: str) -> dict[str, Any]:
    asiento = {"clave": clave, "monto": monto, "puerta": puerta}
    LIBRO.append(asiento)
    CLAVES.add(clave)
    return dict(asiento)


def cobrar(clave: str, monto: float, estricto: bool = True) -> dict[str, Any]:
    del estricto
    validado = validar(clave, monto)
    if _ya_asentada(clave):
        raise Rechazo(f"la clave {clave} ya tiene asiento en el libro")
    return _asentar(clave, validado, "mostrador")


def reenviar(clave: str, monto: float, estricto: bool = True) -> dict[str, Any]:
    del estricto
    validado = validar(clave, monto)
    if _ya_asentada(clave):
        raise Rechazo(f"la clave {clave} ya tiene asiento en el libro")
    return _asentar(clave, validado, "reenvio")


def conciliar(clave: str, monto: float, estricto: bool = True) -> dict[str, Any]:
    # El parche ingenuo se detiene aquí: comprueba en las puertas que el informe nombró y deja
    # esta sin comprobar. La diferencia entre `--naive` y el canónico es una sola línea.
    validado = validar(clave, monto)
    if estricto and _ya_asentada(clave):
        raise Rechazo(f"la clave {clave} ya tiene asiento en el libro")
    return _asentar(clave, validado, "conciliacion")


def asientos_de(clave: str) -> list[dict[str, Any]]:
    return [dict(a) for a in LIBRO if a["clave"] == clave]


def total_cobrado() -> float:
    return round(float(sum(a["monto"] for a in LIBRO)), 2)


def claves_apuntadas() -> int:
    return len(CLAVES)


def snapshot() -> list[dict[str, Any]]:
    return [dict(a) for a in LIBRO]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Libro de cobros, corregido.")
    parser.add_argument("--clave", default="P-1")
    parser.add_argument("--monto", type=float, default=MONTO_AUTORIZADO)
    args = parser.parse_args(argv)
    print("asiento:", cobrar(args.clave, args.monto))
    try:
        cobrar(args.clave, args.monto)
    except Rechazo as exc:
        print("el reintento no se asienta:", exc)
    print(f"el libro suma {total_cobrado()!r} · asientos: {len(snapshot())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
