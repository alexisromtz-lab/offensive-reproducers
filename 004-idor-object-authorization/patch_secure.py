#!/usr/bin/env python3
"""Parche de la autorización a nivel de objeto, en dos versiones.

HUELLA-OFFREP-004-PARCHE-20261113

    python3 patch_secure.py                       # canónico
    python3 patch_secure.py --naive               # el que cierra el caso reportado

El canónico decide con **un** predicado, `puede(sesion, objeto)`, y lo evalúa en la puerta
única antes de mirar la ruta:

1. el sujeto sale del token firmado, nunca de una cabecera del cliente;
2. el índice está **particionado por inquilino**, así que un identificador ajeno no es
   direccionable aunque se conozca;
3. la ruta de lista no acepta que el cliente elija el dueño: el filtro tiene que ser él
   mismo, o no se atiende;
4. la escritura pasa por el mismo predicado y por una lista blanca de campos;
5. toda ruta no reconocida se rechaza.

El ingenuo arregla **la petición que se reportó**: añade la comprobación de dueño en la
lectura de un objeto suelto. Tres decisiones quedan fuera —el inquilino, la cabecera y la
escritura— y por eso el mismo ataque entra por otras tres puertas.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from typing import Any

CLAVE = b"clave-de-laboratorio-004-no-usar-fuera-de-la-capsula"
SEPARADOR = "."
INQUILINOS = ("norte", "sur")
CUENTAS = {
    ("ana", "norte"), ("beto", "norte"),
    ("ana", "sur"), ("beto", "sur"),
}
CAMPOS_ESCRIBIBLES = {"titulo"}

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


def _cuerpo(usuario: str, tenant: str) -> bytes:
    return json.dumps({"usuario": usuario, "tenant": tenant}, sort_keys=True,
                      separators=(",", ":")).encode()


def _firmar(cuerpo: bytes) -> str:
    return hmac.new(CLAVE, cuerpo, hashlib.sha256).hexdigest()


def emitir(usuario: str, tenant: str, estricto: bool = True) -> str:
    """Token: cuerpo en base64 y, en el canónico, su firma. El ingenuo sigue sin firmar."""
    if (usuario, tenant) not in CUENTAS:
        raise SesionInvalida(f"no existe la cuenta {usuario}@{tenant}")
    cuerpo = _cuerpo(usuario, tenant)
    codificado = base64.b64encode(cuerpo).decode()
    return f"{codificado}{SEPARADOR}{_firmar(cuerpo)}" if estricto else codificado


def sesion_de(token: str, estricto: bool = True) -> dict[str, str]:
    if estricto:
        codificado, _, firma = token.partition(SEPARADOR)
        try:
            cuerpo = base64.b64decode(codificado.encode(), validate=True)
        except Exception as exc:
            raise SesionInvalida(f"token ilegible: {type(exc).__name__}") from exc
        # La integridad se decide antes de interpretar el cuerpo.
        if not hmac.compare_digest(firma, _firmar(cuerpo)):
            raise SesionInvalida("la firma del token no corresponde")
    else:
        try:
            cuerpo = base64.b64decode(token.encode(), validate=True)
        except Exception as exc:
            raise SesionInvalida(f"token ilegible: {type(exc).__name__}") from exc

    try:
        datos = json.loads(cuerpo)
    except Exception as exc:
        raise SesionInvalida(f"el cuerpo no es JSON: {type(exc).__name__}") from exc
    if not isinstance(datos, dict) or set(datos) != {"usuario", "tenant"}:
        raise SesionInvalida("el token no tiene la forma de una sesión")
    if datos["tenant"] not in INQUILINOS or (datos["usuario"], datos["tenant"]) not in CUENTAS:
        raise SesionInvalida("el token nombra una cuenta que no existe")
    return {"usuario": str(datos["usuario"]), "tenant": str(datos["tenant"])}


def usuario_efectivo(sesion: dict[str, str], cabeceras: dict[str, str] | None,
                    estricto: bool = True) -> str:
    """Quién pregunta. El canónico no le da voto a la cabecera; el ingenuo se lo da."""
    if not estricto and cabeceras and cabeceras.get("X-Usuario"):
        return cabeceras["X-Usuario"]
    return sesion["usuario"]


def puede(sesion: dict[str, str], objeto: dict[str, Any]) -> bool:
    """El único predicado de autorización. Inquilino **y** dueño, en ese orden."""
    return objeto["tenant"] == sesion["tenant"] and objeto["dueno"] == sesion["usuario"]


def _del_inquilino(sesion: dict[str, str], oid: str) -> dict[str, Any]:
    """Índice particionado: un identificador de otro inquilino no existe desde aquí."""
    try:
        objeto = OBJETOS[int(oid)]
    except (KeyError, ValueError) as exc:
        raise NoEncontrado(f"no hay objeto {oid!r}") from exc
    if objeto["tenant"] != sesion["tenant"]:
        raise NoEncontrado(f"no hay objeto {oid!r} en el inquilino de la sesión")
    return objeto


def _objeto_suelto(sesion: dict[str, str], oid: str) -> dict[str, Any]:
    try:
        return OBJETOS[int(oid)]
    except (KeyError, ValueError) as exc:
        raise NoEncontrado(f"no hay objeto {oid!r}") from exc


def atender(token: str, metodo: str, ruta: str, cuerpo: dict[str, Any] | None = None,
            cabeceras: dict[str, str] | None = None, estricto: bool = True) -> Any:
    sesion = sesion_de(token, estricto=estricto)
    metodo = metodo.upper()

    if metodo == "GET" and ruta.startswith("/objetos/"):
        oid = ruta.rsplit("/", 1)[1]
        if not estricto:
            # El arreglo reportado: mirar el dueño… preguntando quién dice ser el cliente.
            objeto = _objeto_suelto(sesion, oid)
            if objeto["dueno"] != usuario_efectivo(sesion, cabeceras, estricto=False):
                raise NoAutorizado(f"el objeto {oid} no es de quien pregunta")
            return dict(objeto)
        objeto = _del_inquilino(sesion, oid)
        if not puede(sesion, objeto):
            raise NoAutorizado(f"el objeto {oid} no es de quien pregunta")
        return dict(objeto)

    if metodo == "GET" and ruta.startswith("/objetos?"):
        consulta = dict(par.split("=", 1) for par in ruta.split("?", 1)[1].split("&") if "=" in par)
        dueno = consulta.get("dueno", "")
        if not estricto:
            return [dict(o) for o in OBJETOS.values() if o["dueno"] == dueno]
        if dueno != sesion["usuario"]:
            raise NoAutorizado("el filtro de dueño sólo puede nombrar a la propia sesión")
        return [dict(o) for o in OBJETOS.values()
                if puede(sesion, o)]

    if metodo == "PATCH" and ruta.startswith("/objetos/"):
        oid = ruta.rsplit("/", 1)[1]
        if not estricto:
            objeto = _objeto_suelto(sesion, oid)
            for campo, valor in (cuerpo or {}).items():
                objeto[campo] = valor
            return dict(objeto)
        objeto = _del_inquilino(sesion, oid)
        if not puede(sesion, objeto):
            raise NoAutorizado(f"el objeto {oid} no es de quien pregunta")
        ajenos = set(cuerpo or {}) - CAMPOS_ESCRIBIBLES
        if ajenos:
            raise NoAutorizado(f"campos no escribibles: {sorted(ajenos)}")
        for campo, valor in (cuerpo or {}).items():
            objeto[campo] = valor
        return dict(objeto)

    raise NoEncontrado(f"no hay ruta {metodo} {ruta}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Servicio de objetos con autorizacion por objeto.")
    parser.add_argument("--naive", action="store_true", help="modo ingenuo")
    parser.add_argument("--emitir", nargs=2, metavar=("USUARIO", "TENANT"))
    parser.add_argument("--leer", metavar="TOKEN")
    parser.add_argument("oid", nargs="?")
    args = parser.parse_args(argv)
    estricto = not args.naive

    if args.emitir:
        print(emitir(*args.emitir, estricto=estricto))
        return 0
    if args.leer and args.oid:
        try:
            print(json.dumps(atender(args.leer, "GET", f"/objetos/{args.oid}", estricto=estricto),
                             ensure_ascii=False, sort_keys=True))
        except (SesionInvalida, NoAutorizado, NoEncontrado) as exc:
            print(f"RECHAZADO: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        return 0
    parser.error("hace falta --emitir USUARIO TENANT o --leer TOKEN OID")
    return 20


if __name__ == "__main__":
    raise SystemExit(main())
