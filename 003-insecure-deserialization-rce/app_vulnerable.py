#!/usr/bin/env python3
"""Restaurador de sesiones que confía en el token: la cápsula de la deserialización.

HUELLA-OFFREP-003-APP-20261113

El fallo no está en `pickle`: está en la frontera. El servicio recibe el estado de la
sesión ya serializado por el cliente y lo restaura sin comprobar quién lo escribió ni que
el formato sea el suyo. `pickle` sólo obedece: cuando el flujo trae un `REDUCE`, llama.

Consecuencia: el cliente no envía datos, envía instrucciones. En esta cápsula el efecto es
una llamada a un objeto que el atacante elige; en un despliegue real es ejecución de
código en el proceso del servidor.

    python3 app_vulnerable.py <token_base64>     # restaura e imprime el valor (RC 0)
    python3 app_vulnerable.py --emitir           # imprime un token legítimo de ejemplo

Cuidado: esta cápsula ejecuta código a propósito. No le pases tokens que no haya generado
ella misma.
"""

from __future__ import annotations

import base64
import pickle
import sys
from typing import Any

EJEMPLO = {"usuario": "ana", "rol": "lector", "expira": 1893456000}


class SesionInvalida(Exception):
    """El token no se pudo restaurar como estado de sesión."""


def emitir(estado: dict[str, Any], estricto: bool = True) -> bytes:
    """Serializa el estado. Sin firma: lo que salga de aquí lo puede editar cualquiera."""
    return pickle.dumps(estado, protocol=4)


def restaurar(token: bytes, estricto: bool = True) -> Any:
    """Restaura el estado del token. No hay política: el flujo decide qué se ejecuta."""
    try:
        return pickle.loads(token)
    except Exception as exc:  # un flujo hostil puede romper el lector de cualquier forma
        raise SesionInvalida(f"token no restaurable: {type(exc).__name__}: {exc}") from exc


def autorizar(estado: Any, accion: str) -> bool:
    """Decide por el rol que trae el estado restaurado."""
    if not isinstance(estado, dict):
        return False
    return estado.get("rol") == "admin"


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--emitir":
        print(base64.b64encode(emitir(EJEMPLO)).decode("ascii"))
        return 0
    if len(argv) != 2:
        print("uso: app_vulnerable.py <token_base64> | --emitir", file=sys.stderr)
        return 20
    try:
        token = base64.b64decode(argv[1], validate=True)
    except Exception:
        print("error: el token no es base64", file=sys.stderr)
        return 20
    try:
        estado = restaurar(token)
    except SesionInvalida as exc:
        print(f"ERROR: {exc}")
        return 1
    print(f"RESTAURADO: {estado!r}")
    print(f"admin: {autorizar(estado, 'borrar_todo')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
