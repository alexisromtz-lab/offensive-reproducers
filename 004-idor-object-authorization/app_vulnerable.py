#!/usr/bin/env python3
"""Servicio mínimo de objetos: autentica la sesión y nunca pregunta si el objeto es suyo.

HUELLA-OFFREP-004-APP-20261113

Qué modela
----------
Un API de expedientes con dos inquilinos (`norte`, `sur`) y dos personas con el mismo
nombre en cada uno (`ana`, `beto`). El identificador es único en todo el sistema, así que
`ana` del norte y `ana` del sur **son la misma cadena** para cualquier comprobación que
sólo mire el nombre del dueño.

El fallo es una decisión que falta, no una línea mal escrita: `atender` resuelve la
sesión, resuelve la ruta y devuelve el objeto. Nunca compara el objeto con la sesión.

    python3 app_vulnerable.py --emitir ana norte
    python3 app_vulnerable.py --leer <token> 2

Códigos
-------
0   la petición se atendió
1   la petición fue rechazada
20  argumentos incompatibles
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from typing import Any

INQUILINOS = ("norte", "sur")
CUENTAS = {
    ("ana", "norte"), ("beto", "norte"),
    ("ana", "sur"), ("beto", "sur"),
}

# El identificador es único en todo el sistema: 1..999 son del norte, 1001..1999 del sur.
OBJETOS: dict[int, dict[str, Any]] = {
    1: {"id": 1, "tenant": "norte", "dueno": "ana", "titulo": "acta norte de ana", "estado": "borrador"},
    2: {"id": 2, "tenant": "norte", "dueno": "beto", "titulo": "acta norte de beto", "estado": "borrador"},
    1001: {"id": 1001, "tenant": "sur", "dueno": "ana", "titulo": "acta sur de ana", "estado": "borrador"},
    1002: {"id": 1002, "tenant": "sur", "dueno": "beto", "titulo": "acta sur de beto", "estado": "borrador"},
}


class SesionInvalida(Exception):
    """El token no se puede convertir en una sesión."""


class NoAutorizado(Exception):
    """La sesión existe y el objeto existe, pero no le corresponde."""


class NoEncontrado(Exception):
    """No hay objeto en esa ruta."""


def emitir(usuario: str, tenant: str, estricto: bool = True) -> str:
    """Entrega un token de sesión. Aquí el token es el sujeto, en claro y sin firma."""
    if (usuario, tenant) not in CUENTAS:
        raise SesionInvalida(f"no existe la cuenta {usuario}@{tenant}")
    cuerpo = json.dumps({"usuario": usuario, "tenant": tenant}, sort_keys=True,
                        separators=(",", ":")).encode()
    return base64.b64encode(cuerpo).decode()


def sesion_de(token: str) -> dict[str, str]:
    try:
        datos = json.loads(base64.b64decode(token.encode(), validate=True))
    except Exception as exc:
        raise SesionInvalida(f"token ilegible: {type(exc).__name__}") from exc
    if not isinstance(datos, dict) or set(datos) != {"usuario", "tenant"}:
        raise SesionInvalida("el token no tiene la forma de una sesión")
    return {"usuario": str(datos["usuario"]), "tenant": str(datos["tenant"])}


def usuario_efectivo(sesion: dict[str, str], cabeceras: dict[str, str] | None) -> str:
    """Quién pregunta. La cabecera del cliente gana; la sesión queda de reserva."""
    if cabeceras and cabeceras.get("X-Usuario"):
        return cabeceras["X-Usuario"]
    return sesion["usuario"]


def _objeto(oid: str) -> dict[str, Any]:
    try:
        return OBJETOS[int(oid)]
    except (KeyError, ValueError) as exc:
        raise NoEncontrado(f"no hay objeto {oid!r}") from exc


def atender(token: str, metodo: str, ruta: str, cuerpo: dict[str, Any] | None = None,
            cabeceras: dict[str, str] | None = None, estricto: bool = True) -> Any:
    """Puerta única del servicio: una ruta, un método, cero comparación con la sesión."""
    sesion_de(token)  # se resuelve la sesión… y no se vuelve a usar

    metodo = metodo.upper()
    if metodo == "GET" and ruta.startswith("/objetos/"):
        return dict(_objeto(ruta.rsplit("/", 1)[1]))

    if metodo == "GET" and ruta.startswith("/objetos?"):
        consulta = dict(par.split("=", 1) for par in ruta.split("?", 1)[1].split("&") if "=" in par)
        dueno = consulta.get("dueno", "")
        return [dict(o) for o in OBJETOS.values() if o["dueno"] == dueno]

    if metodo == "PATCH" and ruta.startswith("/objetos/"):
        objeto = _objeto(ruta.rsplit("/", 1)[1])
        for campo, valor in (cuerpo or {}).items():
            objeto[campo] = valor
        return dict(objeto)

    raise NoEncontrado(f"no hay ruta {metodo} {ruta}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Servicio de objetos con autorizacion ausente.")
    parser.add_argument("--emitir", nargs=2, metavar=("USUARIO", "TENANT"),
                        help="emite un token de sesión")
    parser.add_argument("--leer", metavar="TOKEN", help="lee un objeto con ese token")
    parser.add_argument("oid", nargs="?", help="identificador del objeto")
    args = parser.parse_args(argv)

    if args.emitir:
        print(emitir(*args.emitir))
        return 0
    if args.leer and args.oid:
        try:
            print(json.dumps(atender(args.leer, "GET", f"/objetos/{args.oid}"),
                             ensure_ascii=False, sort_keys=True))
        except (SesionInvalida, NoAutorizado, NoEncontrado) as exc:
            print(f"RECHAZADO: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        return 0
    parser.error("hace falta --emitir USUARIO TENANT o --leer TOKEN OID")
    return 20


if __name__ == "__main__":
    raise SystemExit(main())
