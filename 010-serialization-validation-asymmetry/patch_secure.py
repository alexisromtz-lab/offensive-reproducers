#!/usr/bin/env python3
"""El mismo libro de cobros, en dos versiones.

HUELLA-OFFREP-010-PARCHE-20261116

    python3 patch_secure.py --orden A-1 --monto 5 --techo 10            # canónico
    python3 patch_secure.py --orden A-1 --monto 5 --techo 10 --naive    # el que cierra el informe

Canónico
--------
Dos reglas, y la segunda es la que importa:

1. `_validar_canonico` rechaza en la frontera lo que la codificación no puede representar
   (`math.isfinite`). Un valor que no sobrevive a la serialización no entra.
2. **Se guarda y se relee antes de dar el asiento por bueno.** Si la instantánea no devuelve
   exactamente lo validado, la escritura se rechaza. Esta regla no necesita saber cuál es el
   valor problemático: comprueba la propiedad, no el caso.

Y la lectura falla cerrada: un asiento sin monto **no** se lee como «sin techo».

Ingenuo
-------
Cierra el caso que el informe nombra —«un cobro con `monto: 1e400` eludió el techo»— poniendo
la comprobación del lado de la lectura: un asiento sin monto ya no se admite. El techo vuelve a
aplicarse y el informe se cierra.

Lo que el ingenuo **no** toca es la escritura, así que la clase de fallo sigue entera: el valor
validado sigue sin ser el valor guardado. El asiento «cobro de `null`» sigue naciendo de un monto
que el servicio aceptó, y cualquier otra regla que lea ese asiento —un reembolso, un total, una
conciliación— sigue leyendo un dato que no es el que se validó.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from typing import Any

LIBRO: dict[str, dict[str, Any]] = {}


class Rechazo(ValueError):
    """Rechazo declarado en la frontera: quien lo recibe lo lee como cierre, no como rotura."""


def _validar_ingenuo(monto: float) -> float:
    if monto < 0:
        raise Rechazo(f"monto negativo: {monto!r}")
    return monto


def _validar_canonico(monto: float) -> float:
    if not math.isfinite(monto):
        raise Rechazo(f"monto no representable en JSON: {monto!r}")
    if monto < 0:
        raise Rechazo(f"monto negativo: {monto!r}")
    return monto


def _a_json(monto: float) -> float | None:
    if not math.isfinite(monto):
        return None
    return monto


def _registrar_ingenuo(orden_id: str, monto: float, techo: float) -> dict[str, Any]:
    instantanea = {"orden": orden_id, "monto": _a_json(monto), "techo": techo}
    LIBRO[orden_id] = json.loads(json.dumps(instantanea))
    return dict(LIBRO[orden_id])


def _registrar_canonico(orden_id: str, monto: float, techo: float) -> dict[str, Any]:
    validado = _validar_canonico(monto)
    instantanea = {"orden": orden_id, "monto": _a_json(validado), "techo": techo}
    guardado = json.loads(json.dumps(instantanea))
    if guardado["monto"] != validado:
        # La propiedad que hace falta: lo que se guarda vuelve igual. Sin esta comprobación,
        # cada codificación nueva hay que revisarla a mano.
        raise Rechazo(f"la instantanea no devuelve lo validado: "
                      f"{validado!r} -> {guardado['monto']!r}")
    LIBRO[orden_id] = guardado
    return dict(guardado)


def registrar_cobro(orden_id: str, monto: float, techo: float,
                    estricto: bool = True) -> dict[str, Any]:
    if estricto:
        return _registrar_canonico(orden_id, monto, techo)
    return _registrar_ingenuo(orden_id, monto, techo)


def puede_cobrar(orden_id: str, estricto: bool = True) -> bool:
    _ = estricto
    asiento = LIBRO.get(orden_id)
    if asiento is None:
        return False
    guardado = asiento["monto"]
    if guardado is None:
        # Las dos versiones fallan cerradas aquí: el ingenuo cierra el caso reportado sin
        # tocar la escritura, y por eso la clase sigue abierta.
        return False
    return guardado <= asiento["techo"]


def total_cobrado() -> float:
    return sum((asiento["monto"] or 0.0 for asiento in LIBRO.values()), 0.0)


def snapshot() -> dict[str, dict[str, Any]]:
    return {orden: dict(asiento) for orden, asiento in LIBRO.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Libro de cobros con techo por orden.")
    parser.add_argument("--orden", required=True)
    parser.add_argument("--monto", required=True)
    parser.add_argument("--techo", type=float, required=True)
    parser.add_argument("--naive", action="store_true", help="modo ingenuo")
    args = parser.parse_args(argv)

    estricto = not args.naive
    try:
        asiento = registrar_cobro(args.orden, float(args.monto), args.techo, estricto=estricto)
    except Rechazo as exc:
        print(f"RECHAZADO: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(asiento))
    print(f"COBRA: {'si' if puede_cobrar(args.orden, estricto=estricto) else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
