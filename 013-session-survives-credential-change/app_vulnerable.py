#!/usr/bin/env python3
"""Cuentas: la credencial cambia y todo lo que la anterior habia emitido sigue valiendo.

HUELLA-OFFREP-013-APP-20261117

Que modela
----------
El flujo que cualquiera reconoce: una contrasena se filtra, el usuario pide un enlace, cambia la
contrasena, y espera que el intruso se quede fuera. Tres piezas, y lo que las une:

1. `restablecer` — la credencial nueva se asienta en `USUARIOS`. Es el efecto que el usuario
   pidio, y ocurre de verdad: la credencial vieja deja de entrar en el acto.
2. `entrar` — abre una sesion **y anota con que credencial nacio**.
3. `abrir_persistente` — abre una concesion de refresco, con la misma anotacion.

El defecto no es que existan sesiones ni concesiones —cualquier servicio real las tiene— ni que
el cambio de credencial falle. El defecto es que `autorizar` y `refrescar` tienen la anotacion
delante y **no la preguntan**: lo emitido con la credencial vieja se sigue honrando despues del
cambio. Quien tenga una sesion abierta o una concesion de refresco no necesita la contrasena: ya
esta dentro, y puede volver a entrar cuando quiera.

    python3 app_vulnerable.py
    python3 app_vulnerable.py --clave-nueva otra-clave-bien-larga

Codigos
-------
0   el cambio se asento, y se informa del estado de lo ya emitido
1   la credencial nueva no se pudo asentar
20  argumentos incompatibles
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

USUARIO = "ana"
CLAVE_INICIAL = "contrasena-de-la-tienda"
CLAVE_NUEVA = "caballo-correcto-bateria"
LARGO_MINIMO = 12

USUARIOS: dict[str, dict[str, Any]] = {}
SESIONES: dict[str, dict[str, Any]] = {}
CONCESIONES: dict[str, dict[str, Any]] = {}
TOKENS: dict[str, dict[str, Any]] = {}
SECUENCIA = 0


class Rechazo(ValueError):
    """Rechazo declarado en la frontera: quien lo recibe lo lee como cierre, no como rotura."""


def _huella(clave: str) -> str:
    return hashlib.sha256(clave.encode("utf-8")).hexdigest()


def _nuevo(prefijo: str) -> str:
    global SECUENCIA
    SECUENCIA += 1
    return f"{prefijo}-{SECUENCIA:04d}"


def reiniciar() -> None:
    global SECUENCIA
    USUARIOS.clear()
    SESIONES.clear()
    CONCESIONES.clear()
    TOKENS.clear()
    SECUENCIA = 0
    USUARIOS[USUARIO] = {"clave": _huella(CLAVE_INICIAL)}


def _exigir_credencial(usuario: str, clave: str) -> dict[str, Any]:
    cuenta = USUARIOS.get(usuario)
    if cuenta is None or cuenta["clave"] != _huella(clave):
        raise Rechazo("credencial invalida")
    return cuenta


def entrar(usuario: str, clave: str) -> str:
    cuenta = _exigir_credencial(usuario, clave)
    sid = _nuevo("sid")
    # La anotacion se guarda para la auditoria: con que credencial nacio esta sesion.
    SESIONES[sid] = {"usuario": usuario, "credencial": cuenta["clave"], "revocada": False}
    return sid


def abrir_persistente(usuario: str, clave: str) -> str:
    cuenta = _exigir_credencial(usuario, clave)
    concesion = _nuevo("con")
    CONCESIONES[concesion] = {"usuario": usuario, "credencial": cuenta["clave"],
                              "revocada": False}
    return concesion


def solicitar(usuario: str) -> str:
    if usuario not in USUARIOS:
        raise Rechazo(f"usuario desconocido: {usuario!r}")
    token = _nuevo("tok")
    TOKENS[token] = {"usuario": usuario, "gastado": False}
    return token


def _pendiente(token: str, clave_nueva: str) -> tuple[str, dict[str, Any]]:
    pendiente = TOKENS.get(token)
    if pendiente is None:
        raise Rechazo("token desconocido")
    if pendiente["gastado"]:
        raise Rechazo("token ya gastado")
    if len(clave_nueva) < LARGO_MINIMO:
        raise Rechazo(f"la clave no cumple la politica: minimo {LARGO_MINIMO} caracteres")
    return str(pendiente["usuario"]), pendiente


def restablecer(token: str, clave_nueva: str, estricto: bool = True) -> dict[str, Any]:
    _ = estricto
    usuario, pendiente = _pendiente(token, clave_nueva)
    # El efecto: la credencial nueva se asienta. Y la funcion termina aqui: lo que la credencial
    # vieja ya habia emitido no se toca, porque nada de lo emitido se pregunta con que nacio.
    USUARIOS[usuario]["clave"] = _huella(clave_nueva)
    pendiente["gastado"] = True
    return {"usuario": usuario, "clave": "asentada"}


def autorizar(sid: str, estricto: bool = True) -> dict[str, Any]:
    _ = estricto
    sesion = SESIONES.get(sid)
    if sesion is None:
        raise Rechazo("sesion desconocida")
    if sesion["revocada"]:
        raise Rechazo("sesion revocada")
    return {"usuario": sesion["usuario"]}


def refrescar(concesion: str, estricto: bool = True) -> str:
    _ = estricto
    pendiente = CONCESIONES.get(concesion)
    if pendiente is None:
        raise Rechazo("concesion desconocida")
    if pendiente["revocada"]:
        raise Rechazo("concesion revocada")
    sid = _nuevo("sid")
    SESIONES[sid] = {"usuario": pendiente["usuario"],
                     "credencial": pendiente["credencial"], "revocada": False}
    return sid


def sesion_vigente(sid: str, estricto: bool = True) -> bool:
    """El sistema preguntado por el estado, sin excepcion de por medio."""
    _ = estricto
    sesion = SESIONES.get(sid)
    return bool(sesion) and not sesion["revocada"]


def concesion_vigente(concesion: str, estricto: bool = True) -> bool:
    _ = estricto
    pendiente = CONCESIONES.get(concesion)
    return bool(pendiente) and not pendiente["revocada"]


def credencial_vigente(usuario: str) -> str:
    cuenta = USUARIOS.get(usuario)
    return "" if cuenta is None else str(cuenta["clave"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cuentas con cambio de credencial.")
    parser.add_argument("--usuario", default=USUARIO)
    parser.add_argument("--clave-vieja", default=CLAVE_INICIAL)
    parser.add_argument("--clave-nueva", default=CLAVE_NUEVA)
    args = parser.parse_args(argv)

    reiniciar()
    try:
        sid = entrar(args.usuario, args.clave_vieja)
        concesion = abrir_persistente(args.usuario, args.clave_vieja)
        token = solicitar(args.usuario)
        restablecer(token, args.clave_nueva)
    except Rechazo as exc:
        print(f"RECHAZADO: {exc}", file=sys.stderr)
        return 1

    sesion = "viva" if sesion_vigente(sid) else "revocada"
    refresco = "vivo" if concesion_vigente(concesion) else "revocado"
    print(json.dumps({"credencial": "cambiada", "sesion_anterior": sesion,
                      "concesion_anterior": refresco}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
