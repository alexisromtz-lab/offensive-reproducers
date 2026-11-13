#!/usr/bin/env python3
"""Restaurador de sesiones con integridad y esquema: el parche canónico y el ingenuo.

HUELLA-OFFREP-003-PARCHE-20261113

Qué cambia
----------
El token deja de ser un programa y pasa a ser un dato firmado:

  1. el cuerpo se serializa en JSON, no en `pickle`: un formato que no tiene forma de
     nombrar una función, así que no hay nada que ejecutar aunque el flujo sea hostil;
  2. el cuerpo viaja con una firma HMAC-SHA256 y se verifica con `hmac.compare_digest`
     ANTES de mirar un solo byte del contenido: en tiempo constante y en el orden
     correcto (parse-then-verify es ejecutar y luego preguntar quién era);
  3. el contenido se valida contra un esquema cerrado —qué campos, de qué tipo exacto y
     qué valores— porque el token lo escribió el cliente;
  4. el rol `admin` no está en el esquema: la autoridad no viaja en el token.

El modo ingenuo
---------------
`restaurar(token, estricto=False)` reproduce el primer parche que se escribe en la
práctica: dejar `pickle` donde está y buscar palabras peligrosas en los bytes del flujo
(`posix`, `system`, `os`, `subprocess`). Cierra el gadget de libro y nada más: la lista es
finita, el nombre del `GLOBAL` es cualquiera que sea importable, y la búsqueda por
subcadena además rechaza tráfico legítimo (un usuario llamado «costa» contiene `os`).

    python3 exploit_poc.py --app patch_secure.py --naive   # RC 0: sigue entrando
    python3 exploit_poc.py --app patch_secure.py           # RC 1: bloqueado

Cuidado: el modo ingenuo también ejecuta `pickle`. No le pases tokens que no conozcas.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import pickle
import sys
from typing import Any

# Clave de laboratorio: en un despliegue real cada servicio tiene la suya y no viaja en el
# código. Aquí está escrita para que la cápsula corra sin configuración.
CLAVE = b"clave-de-laboratorio-003-no-usar-fuera-de-la-capsula"
SEPARADOR = b"."
CAMPOS = {"usuario": str, "rol": str, "expira": int}
ROLES = frozenset({"lector", "editor"})

# Lista negra del parche ingenuo: compara subcadenas de los bytes, no capacidades.
LISTA_NEGRA = (b"posix", b"nt.", b"system", b"subprocess", b"popen", b"os")

EJEMPLO = {"usuario": "ana", "rol": "lector", "expira": 1893456000}


class SesionInvalida(Exception):
    """El token no se pudo restaurar como estado de sesión."""


class FirmaInvalida(SesionInvalida):
    """El token no trae una firma válida: no sabemos quién lo escribió."""


class EsquemaInvalido(SesionInvalida):
    """El token está firmado, pero su contenido no es el estado de sesión que esperamos."""


def _firmar(cuerpo: bytes) -> bytes:
    return hmac.new(CLAVE, cuerpo, hashlib.sha256).hexdigest().encode("ascii")


def emitir(estado: dict[str, Any], estricto: bool = True) -> bytes:
    """Emite un token firmado. El servidor es el único que puede llamar a esto bien."""
    if not estricto:
        return pickle.dumps(estado, protocol=4)
    cuerpo = json.dumps(estado, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _firmar(cuerpo) + SEPARADOR + cuerpo


def restaurar(token: bytes, estricto: bool = True) -> Any:
    """Restaura el estado si —y sólo si— la firma y el esquema lo admiten."""
    if not estricto:
        return _restaurar_ingenuo(token)
    firma, separador, cuerpo = token.partition(SEPARADOR)
    if not separador:
        raise FirmaInvalida("el token no trae firma separada del cuerpo")
    if not hmac.compare_digest(firma, _firmar(cuerpo)):
        raise FirmaInvalida("la firma no corresponde al cuerpo: el token fue alterado o no es nuestro")
    try:
        estado = json.loads(cuerpo.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EsquemaInvalido(f"el cuerpo firmado no es JSON: {exc}") from exc
    _validar_esquema(estado)
    return estado


def _restaurar_ingenuo(token: bytes) -> Any:
    for palabra in LISTA_NEGRA:
        if palabra in token:
            raise SesionInvalida(f"token rechazado: contiene {palabra!r}")
    try:
        return pickle.loads(token)
    except Exception as exc:
        raise SesionInvalida(f"token no restaurable: {type(exc).__name__}: {exc}") from exc


def _validar_esquema(estado: Any) -> None:
    if not isinstance(estado, dict):
        raise EsquemaInvalido(f"se esperaba un objeto, llego {type(estado).__name__}")
    if set(estado) != set(CAMPOS):
        raise EsquemaInvalido(f"campos inesperados: {sorted(set(estado) ^ set(CAMPOS))}")
    for campo, tipo in CAMPOS.items():
        # `type(...) is` y no `isinstance(...)`: `True` es un `int` para isinstance.
        if type(estado[campo]) is not tipo:  # noqa: E721 - la identidad de tipo es el contrato
            raise EsquemaInvalido(
                f"{campo} debe ser {tipo.__name__}, llego {type(estado[campo]).__name__}")
    if estado["rol"] not in ROLES:
        raise EsquemaInvalido(f"rol no admitido: {estado['rol']!r} (admitidos: {sorted(ROLES)})")


def autorizar(estado: Any, accion: str) -> bool:
    """Decide por el rol que trae el estado restaurado. No cambió: cambió lo que llega."""
    if not isinstance(estado, dict):
        return False
    return estado.get("rol") == "admin"


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--emitir":
        print(base64.b64encode(emitir(EJEMPLO)).decode("ascii"))
        return 0
    estricto = True
    argumentos = argv[1:]
    if argumentos and argumentos[0] == "--naive":
        estricto = False
        argumentos = argumentos[1:]
    if len(argumentos) != 1:
        print("uso: patch_secure.py [--naive] <token_base64> | --emitir", file=sys.stderr)
        return 20
    try:
        token = base64.b64decode(argumentos[0], validate=True)
    except Exception:
        print("error: el token no es base64", file=sys.stderr)
        return 20
    try:
        estado = restaurar(token, estricto=estricto)
    except SesionInvalida as exc:
        print(f"DENEGADO: {exc}")
        return 1
    print(f"RESTAURADO: {estado!r}")
    print(f"admin: {autorizar(estado, 'borrar_todo')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
