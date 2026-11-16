#!/usr/bin/env python3
"""La misma caja con registro, en dos versiones.

HUELLA-OFFREP-011-PARCHE-20261116

    python3 patch_secure.py --orden A-1 --monto 10              # canónico
    python3 patch_secure.py --orden A-1 --monto 10 --naive      # el que cierra el informe

Canónico
--------
Dos reglas, y el orden entre ellas es lo que importa:

1. **El rastro va antes del efecto.** El evento se entrega al sumidero *antes* de asentar el
   movimiento; si el sumidero no lo admite, la operación se rechaza. La caja prefiere no mover
   dinero a moverlo sin poder contarlo.
2. **Se relee el sumidero.** Si no devuelve el evento que se le entregó, la operación se rechaza.
   Esta regla no necesita saber por qué falló el sumidero: comprueba la propiedad, no el caso.

Y el panel cuenta en el sumidero, no en el sitio de llamada, así que una brecha se ve en vez de
publicarse como cuadre.

Ingenuo
-------
Cierra el caso que el informe nombra —«el panel decía brecha cero con el sumidero caído»—
poniendo la cuenta del lado del sumidero. La brecha se vuelve visible y el informe se cierra.

Lo que el ingenuo **no** toca es el orden: el movimiento se sigue asentando antes de que el
rastro exista, y el fallo del sumidero se sigue absorbiendo. El panel ahora avisa de una
operación que ya ocurrió y que nadie puede reconstruir: se mejoró la detección y se dejó intacta
la pérdida.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

MOVIMIENTOS: dict[str, dict[str, Any]] = {}
SUMIDERO: list[dict[str, Any]] = []
SUMIDERO_CAIDO = False


class Rechazo(ValueError):
    """Rechazo declarado en la frontera: quien lo recibe lo lee como cierre, no como rotura."""


class SumideroNoDisponible(OSError):
    """El sumidero no admite escrituras."""


def reiniciar(sumidero_caido: bool = False) -> None:
    global SUMIDERO_CAIDO
    MOVIMIENTOS.clear()
    SUMIDERO.clear()
    SUMIDERO_CAIDO = sumidero_caido


def _escribir_evento(evento: dict[str, Any]) -> None:
    if SUMIDERO_CAIDO:
        raise SumideroNoDisponible("el sumidero no admite escrituras")
    SUMIDERO.append(dict(evento))


def _validar(monto: float) -> float:
    if monto <= 0:
        raise Rechazo(f"monto no positivo: {monto!r}")
    return monto


def _evento(orden_id: str, monto: float) -> dict[str, Any]:
    return {"orden": orden_id, "monto": monto, "tipo": "transferencia"}


def _ejecutar_ingenuo(orden_id: str, monto: float) -> dict[str, Any]:
    _validar(monto)
    MOVIMIENTOS[orden_id] = {"orden": orden_id, "monto": monto}
    try:
        _escribir_evento(_evento(orden_id, monto))
    except SumideroNoDisponible:
        pass
    return dict(MOVIMIENTOS[orden_id])


def _ejecutar_canonico(orden_id: str, monto: float) -> dict[str, Any]:
    _validar(monto)
    evento = _evento(orden_id, monto)
    try:
        _escribir_evento(evento)
    except SumideroNoDisponible as exc:
        raise Rechazo(f"sin rastro durable no hay operación: {exc}") from exc
    if not SUMIDERO or SUMIDERO[-1] != evento:
        raise Rechazo("el sumidero no devuelve el evento que se le entregó")
    MOVIMIENTOS[orden_id] = {"orden": orden_id, "monto": monto}
    return dict(MOVIMIENTOS[orden_id])


def ejecutar(orden_id: str, monto: float, estricto: bool = True) -> dict[str, Any]:
    if estricto:
        return _ejecutar_canonico(orden_id, monto)
    return _ejecutar_ingenuo(orden_id, monto)


def movimientos() -> dict[str, dict[str, Any]]:
    return {orden: dict(movimiento) for orden, movimiento in MOVIMIENTOS.items()}


def hay_rastro(orden_id: str) -> bool:
    return any(evento["orden"] == orden_id for evento in SUMIDERO)


def eventos_durables() -> list[dict[str, Any]]:
    return [dict(evento) for evento in SUMIDERO]


def vigilancia(estricto: bool = True) -> dict[str, Any]:
    """El panel cuenta en el sumidero: lo que no se conservó no se cuenta como registrado."""
    _ = estricto
    operaciones = len(MOVIMIENTOS)
    eventos = len(SUMIDERO)
    return {"operaciones": operaciones, "eventos": eventos,
            "brecha": operaciones - eventos, "durables": len(SUMIDERO)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Caja con registro de auditoría.")
    parser.add_argument("--orden", required=True)
    parser.add_argument("--monto", type=float, required=True)
    parser.add_argument("--sumidero-caido", action="store_true",
                        help="el sumidero no admite escrituras")
    parser.add_argument("--naive", action="store_true",
                        help="la variante que sólo cierra el caso reportado")
    args = parser.parse_args(argv)

    reiniciar(sumidero_caido=args.sumidero_caido)
    try:
        movimiento = ejecutar(args.orden, args.monto, estricto=not args.naive)
    except Rechazo as exc:
        print(f"RECHAZADO: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(movimiento))
    print(f"RASTRO: {'si' if hay_rastro(args.orden) else 'no'}")
    print(json.dumps(vigilancia(estricto=not args.naive)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
