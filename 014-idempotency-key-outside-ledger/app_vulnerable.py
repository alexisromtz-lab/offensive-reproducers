#!/usr/bin/env python3
"""Libro de cobros con clave de idempotencia: el candado vive en el mostrador, no en el libro.

HUELLA-OFFREP-014-APP-20261118

Qué pregunta
------------
Tres puertas escriben en el mismo libro --el mostrador, el aviso del proveedor y la
conciliación del día-- y sólo la primera consulta el registro de claves. La clave de
idempotencia está **fuera** del libro, así que no ata a las otras dos: el mismo evento puede
asentarse dos veces por una puerta que nunca miró el registro, y el libro sigue cuadrando
porque ningún asiento recuerda que su clave ya estaba.

    python3 app_vulnerable.py --clave P-1 --monto 10
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
    """Lo único que las tres puertas comparten es el dato, no el invariante."""
    if not clave:
        raise Rechazo("la clave de idempotencia no puede venir vacia")
    if monto <= 0:
        raise Rechazo(f"monto no positivo: {monto!r}")
    return monto


def _asentar(clave: str, monto: float, puerta: str) -> dict[str, Any]:
    asiento = {"clave": clave, "monto": monto, "puerta": puerta}
    LIBRO.append(asiento)
    return dict(asiento)


def cobrar(clave: str, monto: float, estricto: bool = True) -> dict[str, Any]:
    """El mostrador: la única puerta que mira CLAVES."""
    del estricto  # el mostrador consulta el registro siempre
    validado = validar(clave, monto)
    if clave in CLAVES:
        raise Rechazo(f"la clave {clave} ya se cobro por el mostrador")
    asiento = _asentar(clave, validado, "mostrador")
    CLAVES.add(clave)
    return asiento


def reenviar(clave: str, monto: float, estricto: bool = True) -> dict[str, Any]:
    """El aviso del proveedor: asienta y no consulta el registro."""
    del estricto
    return _asentar(clave, validar(clave, monto), "reenvio")


def conciliar(clave: str, monto: float, estricto: bool = True) -> dict[str, Any]:
    """La conciliación del día: reasienta lo que ya venía en el fichero."""
    del estricto
    return _asentar(clave, validar(clave, monto), "conciliacion")


def asientos_de(clave: str) -> list[dict[str, Any]]:
    return [dict(a) for a in LIBRO if a["clave"] == clave]


def total_cobrado() -> float:
    return round(float(sum(a["monto"] for a in LIBRO)), 2)


def claves_apuntadas() -> int:
    return len(CLAVES)


def snapshot() -> list[dict[str, Any]]:
    return [dict(a) for a in LIBRO]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Libro de cobros del comercio.")
    parser.add_argument("--clave", default="P-1", help="clave de idempotencia del evento")
    parser.add_argument("--monto", type=float, default=MONTO_AUTORIZADO)
    args = parser.parse_args(argv)
    print("asiento:", cobrar(args.clave, args.monto))
    print(f"el libro suma {total_cobrado()!r} · asientos: {len(snapshot())} · "
          f"claves apuntadas por el mostrador: {claves_apuntadas()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
