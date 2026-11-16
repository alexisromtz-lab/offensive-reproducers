#!/usr/bin/env python3
"""Caja con registro de auditoría: la operación se asienta aunque su evento no llegue.

HUELLA-OFFREP-011-APP-20261116

Qué modela
----------
Una caja que mueve dinero y tiene que dejar rastro de cada movimiento. Las tres piezas son las
de cualquier servicio real, y el orden entre ellas es lo que se ataca:

1. `ejecutar` — el movimiento se asienta en el libro. Es el efecto: mueve dinero.
2. `_escribir_evento` — el rastro viaja a un sumidero que puede no admitir escrituras.
3. `vigilancia` — el panel que tiene que notar la diferencia entre lo movido y lo registrado.

El defecto no es que un sumidero falle —los sumideros fallan—: es que su fallo se absorbe
**después** de asentar el efecto, y que el panel cuenta las llamadas al registro en vez de los
asientos que el sumidero conserva. Con el sumidero caído el libro se mueve, el rastro no existe,
y el panel publica brecha cero: perdió el evento que importaba y no lo echó de menos.

    python3 app_vulnerable.py --orden A-1 --monto 10
    python3 app_vulnerable.py --orden A-2 --monto 10 --sumidero-caido

Códigos
-------
0   la operación se atendió
1   la operación fue rechazada
20  argumentos incompatibles
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

MOVIMIENTOS: dict[str, dict[str, Any]] = {}
SUMIDERO: list[dict[str, Any]] = []
LLAMADAS_AL_REGISTRO = 0
SUMIDERO_CAIDO = False


class Rechazo(ValueError):
    """Rechazo declarado en la frontera: quien lo recibe lo lee como cierre, no como rotura."""


class SumideroNoDisponible(OSError):
    """El sumidero no admite escrituras: el fallo que esta cápsula mide."""


def reiniciar(sumidero_caido: bool = False) -> None:
    global LLAMADAS_AL_REGISTRO, SUMIDERO_CAIDO
    MOVIMIENTOS.clear()
    SUMIDERO.clear()
    LLAMADAS_AL_REGISTRO = 0
    SUMIDERO_CAIDO = sumidero_caido


def _escribir_evento(evento: dict[str, Any]) -> None:
    if SUMIDERO_CAIDO:
        raise SumideroNoDisponible("el sumidero no admite escrituras")
    SUMIDERO.append(dict(evento))


def ejecutar(orden_id: str, monto: float, estricto: bool = True) -> dict[str, Any]:
    _ = estricto
    if monto <= 0:
        raise Rechazo(f"monto no positivo: {monto!r}")
    global LLAMADAS_AL_REGISTRO
    # El efecto primero: para cuando el rastro falla, el dinero ya se movió.
    MOVIMIENTOS[orden_id] = {"orden": orden_id, "monto": monto}
    LLAMADAS_AL_REGISTRO += 1
    try:
        _escribir_evento({"orden": orden_id, "monto": monto, "tipo": "transferencia"})
    except SumideroNoDisponible:
        # «El registro no debe tumbar una operación que el cliente ya pagó.» La regla que
        # falla abierta: el fallo del rastro se absorbe y la operación sigue sin dejar huella.
        pass
    return dict(MOVIMIENTOS[orden_id])


def movimientos() -> dict[str, dict[str, Any]]:
    return {orden: dict(movimiento) for orden, movimiento in MOVIMIENTOS.items()}


def hay_rastro(orden_id: str) -> bool:
    return any(evento["orden"] == orden_id for evento in SUMIDERO)


def eventos_durables() -> list[dict[str, Any]]:
    return [dict(evento) for evento in SUMIDERO]


def vigilancia(estricto: bool = True) -> dict[str, Any]:
    """El panel: cuenta en el sitio de llamada, no en el sumidero."""
    _ = estricto
    operaciones = len(MOVIMIENTOS)
    eventos = LLAMADAS_AL_REGISTRO
    return {"operaciones": operaciones, "eventos": eventos,
            "brecha": operaciones - eventos, "durables": len(SUMIDERO)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Caja con registro de auditoría.")
    parser.add_argument("--orden", required=True)
    parser.add_argument("--monto", type=float, required=True)
    parser.add_argument("--sumidero-caido", action="store_true",
                        help="el sumidero no admite escrituras")
    args = parser.parse_args(argv)

    reiniciar(sumidero_caido=args.sumidero_caido)
    try:
        movimiento = ejecutar(args.orden, args.monto)
    except Rechazo as exc:
        print(f"RECHAZADO: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(movimiento))
    print(f"RASTRO: {'si' if hay_rastro(args.orden) else 'no'}")
    print(json.dumps(vigilancia()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
