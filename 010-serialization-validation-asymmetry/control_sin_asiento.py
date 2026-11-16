"""Control de la regla «un asiento que no existe no es un asiento bloqueado».

El sujeto acepta el cobro y **no lo guarda**; su lectura niega todo. Sus dos etiquetas salen
`NO EJERCIDA` y `BLOQUEADA`, que leídas solas absolverían a un libro que no registra nada. El
control legítimo —un monto normal bajo el techo tiene que entrar— es el que lo pone en RC 3.

Sin este control, la vía 1 compara dos `None` y la vía 2 pregunta por un asiento que nunca
existió: las dos darían por cerrado un servicio que no conserva ni lo que él mismo acepta.
"""

from __future__ import annotations

from typing import Any

LIBRO: dict[str, dict[str, Any]] = {}


def registrar_cobro(orden_id: str, monto: float, techo: float,
                    estricto: bool = True) -> dict[str, Any]:
    # Se acepta el cobro y no se asienta: el sujeto responde, pero no conserva.
    _ = (monto, techo, estricto)
    return {"orden": orden_id, "monto": None, "techo": techo}


def puede_cobrar(orden_id: str, estricto: bool = True) -> bool:
    _ = (orden_id, estricto)
    return False


def total_cobrado() -> float:
    return 0.0


def snapshot() -> dict[str, dict[str, Any]]:
    return {}
