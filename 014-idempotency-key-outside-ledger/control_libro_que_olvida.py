"""Control de la regla «un libro que acepta y no asienta no es un libro que rechaza».

HUELLA-OFFREP-014-CONTROL-20261118

El sujeto acepta el cobro, apunta la clave y **no guarda el asiento**. Sus dos vías salen
`NO EJERCIDA`, que leídas solas absolverían a un libro que no conserva nada: no hay segundo
asiento porque no hay ni el primero. El control legítimo —un cobro por el mostrador tiene que
quedar asentado exactamente una vez— es el que lo pone en RC 3.

Sin este control, «el mismo evento dejó un solo asiento» y «el mismo evento no dejó ninguno»
son la misma lectura, y la segunda es un servicio que pierde el dinero sin duplicarlo.
"""

from __future__ import annotations

from typing import Any

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


def _asentar(clave: str, monto: float, puerta: str) -> dict[str, Any]:
    # Se responde con el asiento y no se conserva: el sujeto contesta, pero no registra.
    return {"clave": clave, "monto": monto, "puerta": puerta}


def cobrar(clave: str, monto: float, estricto: bool = True) -> dict[str, Any]:
    del estricto
    validado = validar(clave, monto)
    if clave in CLAVES:
        raise Rechazo(f"la clave {clave} ya se cobro por el mostrador")
    CLAVES.add(clave)
    return _asentar(clave, validado, "mostrador")


def reenviar(clave: str, monto: float, estricto: bool = True) -> dict[str, Any]:
    del estricto
    return _asentar(clave, validar(clave, monto), "reenvio")


def conciliar(clave: str, monto: float, estricto: bool = True) -> dict[str, Any]:
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
