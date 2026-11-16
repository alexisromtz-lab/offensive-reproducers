"""Control de la regla «un servicio que no opera no pierde rastro».

El sujeto rechaza toda operación y su panel publica ceros. Sus dos vías salen `RECHAZADA` y
`NO EJERCIDA`, que leídas solas absolverían a un servicio que no hace nada: no perdió ningún
evento porque no ejecutó ninguno. El control legítimo —una transferencia normal tiene que
ejecutarse **y** dejar rastro— es el que lo pone en RC 3.

Sin este control, la cápsula premiaría con RC 1 al sistema más seguro de todos: el que está
apagado. Para A09 el falso verde tiene esa forma exacta, porque «no hay eventos» se lee como
«no hay incidentes».
"""

from __future__ import annotations

from typing import Any


class Rechazo(ValueError):
    """Rechazo declarado: la operación no se autoriza «por política»."""


def reiniciar(sumidero_caido: bool = False) -> None:
    _ = sumidero_caido


def ejecutar(orden_id: str, monto: float, estricto: bool = True) -> dict[str, Any]:
    _ = (orden_id, monto, estricto)
    raise Rechazo("operación no autorizada por política")


def movimientos() -> dict[str, dict[str, Any]]:
    return {}


def hay_rastro(orden_id: str) -> bool:
    _ = orden_id
    return False


def eventos_durables() -> list[dict[str, Any]]:
    return []


def vigilancia(estricto: bool = True) -> dict[str, Any]:
    _ = estricto
    return {"operaciones": 0, "eventos": 0, "brecha": 0, "durables": 0}
