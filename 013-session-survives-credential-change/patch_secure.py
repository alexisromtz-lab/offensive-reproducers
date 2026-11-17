#!/usr/bin/env python3
"""La misma cuenta, en dos versiones.

HUELLA-OFFREP-013-PARCHE-20261117

    python3 patch_secure.py                                     # canonico
    python3 patch_secure.py --naive                             # el que cierra el informe

Canonico
--------
Una regla, y no toca la funcion que el informe senalaba:

**Quien honra una credencial pregunta con cual nacio.** `autorizar` y `refrescar` comparan la
anotacion que ya estaba guardada —la huella de la credencial con la que se emitio la sesion o la
concesion— contra la credencial vigente del usuario. Si no coinciden, la pieza esta muerta.

`restablecer` queda **igual que en el sujeto vulnerable**. No hay que enumerar almacenes ni
recordar revocar nada: cualquier cambio de credencial —por el enlace, por administracion, por
una migracion futura— invalida por construccion todo lo que nacio con la anterior, y un almacen
nuevo que olvide guardar la anotacion se ve como un campo ausente en vez de como una limpieza
que nadie escribio.

Ingenuo
-------
Cierra el caso que el informe nombra —«la sesion abierta sobrevive al cambio»— recorriendo el
almacen de sesiones del usuario y marcandolas revocadas.

Lo que el ingenuo **no** hace es preguntar con que nacio cada pieza: las concesiones de refresco
del usuario siguen vivas, y una concesion viva emite sesiones nuevas. Se revoco lo que el informe
miraba y se dejo intacta la clase: el intruso cambia de puerta y vuelve a entrar.
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


def _restablecer_canonico(token: str, clave_nueva: str) -> dict[str, Any]:
    # Identico al sujeto vulnerable a proposito: el defecto no estaba aqui.
    usuario, pendiente = _pendiente(token, clave_nueva)
    USUARIOS[usuario]["clave"] = _huella(clave_nueva)
    pendiente["gastado"] = True
    return {"usuario": usuario, "clave": "asentada"}


def _restablecer_ingenuo(token: str, clave_nueva: str) -> dict[str, Any]:
    usuario, pendiente = _pendiente(token, clave_nueva)
    USUARIOS[usuario]["clave"] = _huella(clave_nueva)
    pendiente["gastado"] = True
    for sesion in SESIONES.values():
        if sesion["usuario"] == usuario:
            sesion["revocada"] = True
    return {"usuario": usuario, "clave": "asentada"}


def restablecer(token: str, clave_nueva: str, estricto: bool = True) -> dict[str, Any]:
    if estricto:
        return _restablecer_canonico(token, clave_nueva)
    return _restablecer_ingenuo(token, clave_nueva)


def _nacida_con_la_vigente(anotada: str, usuario: str) -> bool:
    cuenta = USUARIOS.get(usuario)
    return cuenta is not None and str(cuenta["clave"]) == anotada


def autorizar(sid: str, estricto: bool = True) -> dict[str, Any]:
    sesion = SESIONES.get(sid)
    if sesion is None:
        raise Rechazo("sesion desconocida")
    if sesion["revocada"]:
        raise Rechazo("sesion revocada")
    if estricto and not _nacida_con_la_vigente(sesion["credencial"], sesion["usuario"]):
        raise Rechazo("la credencial cambio despues de emitirse esta sesion")
    return {"usuario": sesion["usuario"]}


def refrescar(concesion: str, estricto: bool = True) -> str:
    pendiente = CONCESIONES.get(concesion)
    if pendiente is None:
        raise Rechazo("concesion desconocida")
    if pendiente["revocada"]:
        raise Rechazo("concesion revocada")
    if estricto and not _nacida_con_la_vigente(pendiente["credencial"], pendiente["usuario"]):
        raise Rechazo("la credencial cambio despues de emitirse esta concesion")
    sid = _nuevo("sid")
    SESIONES[sid] = {"usuario": pendiente["usuario"],
                     "credencial": pendiente["credencial"], "revocada": False}
    return sid


def sesion_vigente(sid: str, estricto: bool = True) -> bool:
    sesion = SESIONES.get(sid)
    if not sesion or sesion["revocada"]:
        return False
    return not estricto or _nacida_con_la_vigente(sesion["credencial"], sesion["usuario"])


def concesion_vigente(concesion: str, estricto: bool = True) -> bool:
    pendiente = CONCESIONES.get(concesion)
    if not pendiente or pendiente["revocada"]:
        return False
    return not estricto or _nacida_con_la_vigente(pendiente["credencial"], pendiente["usuario"])


def credencial_vigente(usuario: str) -> str:
    cuenta = USUARIOS.get(usuario)
    return "" if cuenta is None else str(cuenta["clave"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cuentas con cambio de credencial.")
    parser.add_argument("--usuario", default=USUARIO)
    parser.add_argument("--clave-vieja", default=CLAVE_INICIAL)
    parser.add_argument("--clave-nueva", default=CLAVE_NUEVA)
    parser.add_argument("--naive", action="store_true",
                        help="la variante que solo cierra el caso reportado")
    args = parser.parse_args(argv)

    reiniciar()
    try:
        sid = entrar(args.usuario, args.clave_vieja)
        concesion = abrir_persistente(args.usuario, args.clave_vieja)
        token = solicitar(args.usuario)
        restablecer(token, args.clave_nueva, estricto=not args.naive)
    except Rechazo as exc:
        print(f"RECHAZADO: {exc}", file=sys.stderr)
        return 1

    sesion = "viva" if sesion_vigente(sid, estricto=not args.naive) else "revocada"
    refresco = "vivo" if concesion_vigente(concesion, estricto=not args.naive) else "revocado"
    print(json.dumps({"credencial": "cambiada", "sesion_anterior": sesion,
                      "concesion_anterior": refresco}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
