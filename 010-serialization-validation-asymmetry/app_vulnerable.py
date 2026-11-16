#!/usr/bin/env python3
"""Libro de cobros: el monto se valida al entrar y se guarda como instantánea JSON.

HUELLA-OFFREP-010-APP-20261116

Qué modela
----------
Un servicio con un techo por orden. Las tres fronteras son las de cualquier servicio real,
y el orden entre ellas es lo que se ataca:

1. `validar` — el monto tiene que ser un número no negativo.
2. `_a_json` — el asiento se guarda **serializado**, no en memoria.
3. `puede_cobrar` — la decisión se toma leyendo lo guardado, no el valor que se validó.

JSON no tiene `Infinity` ni `NaN`: la codificación de un float no finito es `null`. Así que
un monto que `validar` aceptó puede volver como «no hay monto», y un asiento sin monto se lee
como «sin techo que aplicar».

El monto entra por la red: `json.loads('{"monto": 1e400}')` es JSON válido y devuelve `inf`.

    python3 app_vulnerable.py --orden A-1 --monto 5 --techo 10
    python3 app_vulnerable.py --orden A-2 --monto '{"monto": 1e400}' --json --techo 10

Códigos
-------
0   la operación se atendió
1   la operación fue rechazada
20  argumentos incompatibles
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


def validar(monto: float) -> float:
    """La única regla de entrada: no negativo.

    `nan < 0` y `inf < 0` son los dos `False`, así que los dos pasan. No es un descuido del
    ejemplo: es lo que hace una regla de negocio escrita sobre `<`.
    """
    if monto < 0:
        raise Rechazo(f"monto negativo: {monto!r}")
    return monto


def desde_json(texto: str) -> float:
    """El monto tal como llega de la red: `1e400` desborda a `inf` y sigue siendo JSON válido."""
    return float(json.loads(texto)["monto"])


def _a_json(monto: float) -> float | None:
    """La codificación del asiento: JSON no representa `inf` ni `nan`, y escribe `null`."""
    if not math.isfinite(monto):
        return None
    return monto


def registrar_cobro(orden_id: str, monto: float, techo: float,
                    estricto: bool = True) -> dict[str, Any]:
    _ = estricto
    validado = validar(monto)
    instantanea = {"orden": orden_id, "monto": _a_json(validado), "techo": techo}
    # Lo que queda guardado es el JSON, no el objeto: la frontera de escritura es la serialización.
    LIBRO[orden_id] = json.loads(json.dumps(instantanea))
    return dict(LIBRO[orden_id])


def puede_cobrar(orden_id: str, estricto: bool = True) -> bool:
    _ = estricto
    asiento = LIBRO.get(orden_id)
    if asiento is None:
        return False
    guardado = asiento["monto"]
    if guardado is None:
        # «Sin monto declarado no hay techo que aplicar.» La regla que falla abierta.
        return True
    return guardado <= asiento["techo"]


def total_cobrado() -> float:
    """Lo que el libro suma: un asiento sin monto aporta cero, y el cero no se nota."""
    return sum((asiento["monto"] or 0.0 for asiento in LIBRO.values()), 0.0)


def snapshot() -> dict[str, dict[str, Any]]:
    return {orden: dict(asiento) for orden, asiento in LIBRO.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Libro de cobros con techo por orden.")
    parser.add_argument("--orden", required=True)
    parser.add_argument("--monto", required=True, help="el número, o el JSON crudo con --json")
    parser.add_argument("--techo", type=float, required=True)
    parser.add_argument("--json", action="store_true", help="el monto es un JSON de la red")
    args = parser.parse_args(argv)

    monto = desde_json(args.monto) if args.json else float(args.monto)
    try:
        asiento = registrar_cobro(args.orden, monto, args.techo)
    except Rechazo as exc:
        print(f"RECHAZADO: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(asiento))
    print(f"COBRA: {'si' if puede_cobrar(args.orden) else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
