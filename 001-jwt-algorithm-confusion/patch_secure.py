#!/usr/bin/env python3
"""Versión corregida del mismo servicio: lista blanca de algoritmos, material por algoritmo.

HUELLA-OFFREP-001-PARCHE-20261113

Qué cambia
----------
El algoritmo deja de elegirlo el token. El verificador tiene una lista blanca y, fuera
de ella, no hay camino: no existe una rama que acepte HMAC, así que la clave pública
nunca puede convertirse en secreto de nadie.

El modo ingenuo
---------------
`verify_token(token, estricto=False)` reproduce el parche que suele aparecer primero:
«rechaza alg=none y ya». Cierra el caso fácil y deja abierta la confusión de
algoritmo, porque el material de clave sigue siendo uno solo. Se incluye a propósito:
un parche que no se puede refutar con el mismo PoC no está demostrado.

    python3 exploit_poc.py --app patch_secure.py --naive   # RC 0: sigue entrando
    python3 exploit_poc.py --app patch_secure.py           # RC 1: bloqueado
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time
from typing import Any

_N_HEX = (
    "a1f8160ae2e3c9b465ce8d2d656263362b927dbe29e1f02477fc1625cc90a136"
    "e38bd93497c5b6ea63dd7711e67c7429f956b0fb8a8f089adc4b69893cc1333f"
    "53edd019b87784252fec914fe4857769594bea4280d32c0f55bf62944f130396"
    "bc6e9bdf6ebdd2bda3678eeca0c668f701b38dbffb38c8342ce2fe6d27fade4a"
    "5a4874979dd4b9cf9adec4c75b05852c2c0f5ef8a5c1750392f944e8ed64c110"
    "c6b647609aa4783aeb9c6c9ad755313050638b83665c6f6f7a82a396702a1f64"
    "1b82d3ebf2392219491fb686872c5716f50af8358d9a8b9d17c340728f7f87d8"
    "9a18d8fcab67ad84590c2ecf759339363c07034d6f606f9e21e05456cae5e9a1"
)
_E = 65537
_K = 256

_DIGESTINFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")

ALGORITMOS_PERMITIDOS = frozenset({"RS256"})


class InvalidToken(Exception):
    """El token no verifica. Un solo error y sin detalle."""


def _b64u_dec(texto: str) -> bytes:
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


def _der_len(largo: int) -> bytes:
    if largo < 0x80:
        return bytes([largo])
    crudo = largo.to_bytes((largo.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(crudo)]) + crudo


def _tlv(etiqueta: int, cuerpo: bytes) -> bytes:
    return bytes([etiqueta]) + _der_len(len(cuerpo)) + cuerpo


def _der_int(valor: int) -> bytes:
    crudo = valor.to_bytes((valor.bit_length() + 7) // 8 or 1, "big")
    if crudo[0] & 0x80:
        crudo = b"\x00" + crudo
    return _tlv(0x02, crudo)


def public_pem() -> str:
    """La clave pública sigue siendo pública: en la versión corregida eso ya no importa."""
    _n = int(_N_HEX, 16)
    rsapub = _tlv(0x30, _der_int(_n) + _der_int(_E))
    algid = _tlv(0x30, b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00")
    spki = _tlv(0x30, algid + _tlv(0x03, b"\x00" + rsapub))
    cuerpo = base64.b64encode(spki).decode("ascii")
    lineas = "\n".join(cuerpo[i:i + 64] for i in range(0, len(cuerpo), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{lineas}\n-----END PUBLIC KEY-----\n"


def _emsa_pkcs1_v15(mensaje: bytes) -> bytes:
    t = _DIGESTINFO_SHA256 + hashlib.sha256(mensaje).digest()
    return b"\x00\x01" + b"\xff" * (_K - len(t) - 3) + b"\x00" + t


def _rsa_verify(mensaje: bytes, firma: bytes) -> bool:
    if len(firma) != _K:
        return False
    s = int.from_bytes(firma, "big")
    if s >= int(_N_HEX, 16):
        return False
    return hmac.compare_digest(pow(s, _E, int(_N_HEX, 16)).to_bytes(_K, "big"),
                               _emsa_pkcs1_v15(mensaje))


def _claims(token: str) -> tuple[dict[str, Any], str, str, str]:
    partes = token.split(".")
    if len(partes) != 3:
        raise InvalidToken("el token no tiene tres segmentos")
    cabecera_b64, cuerpo_b64, firma_b64 = partes
    try:
        cabecera = json.loads(_b64u_dec(cabecera_b64))
    except ValueError:
        raise InvalidToken("cabecera ilegible") from None
    if not isinstance(cabecera, dict):
        raise InvalidToken("la cabecera no es un objeto")
    return cabecera, cabecera_b64, cuerpo_b64, firma_b64


def verify_token(token: str, estricto: bool = True) -> dict[str, Any]:
    """Verifica el token contra una lista blanca de algoritmos y devuelve sus claims."""
    cabecera, cabecera_b64, cuerpo_b64, firma_b64 = _claims(token)
    alg = cabecera.get("alg")
    firmado = f"{cabecera_b64}.{cuerpo_b64}".encode("ascii")

    if estricto:
        if alg not in ALGORITMOS_PERMITIDOS:
            raise InvalidToken(f"algoritmo fuera de la lista blanca: {alg!r}")
        valido = _rsa_verify(firmado, _b64u_dec(firma_b64))
    else:
        # Parche ingenuo: se cierra `none` y se deja el material de clave compartido.
        if alg == "none":
            raise InvalidToken("alg=none rechazado")
        if alg == "HS256":
            esperado = hmac.new(public_pem().encode("ascii"), firmado, hashlib.sha256).digest()
            valido = hmac.compare_digest(esperado, _b64u_dec(firma_b64))
        elif alg == "RS256":
            valido = _rsa_verify(firmado, _b64u_dec(firma_b64))
        else:
            raise InvalidToken(f"algoritmo no soportado: {alg!r}")

    if not valido:
        raise InvalidToken("la firma no verifica")

    try:
        claims = json.loads(_b64u_dec(cuerpo_b64))
    except ValueError:
        raise InvalidToken("cuerpo ilegible") from None
    if not isinstance(claims, dict):
        raise InvalidToken("el cuerpo no es un objeto")
    if "exp" in claims:
        caduca = claims["exp"]
        if not isinstance(caduca, (int, float)) or caduca < time.time():
            raise InvalidToken("token expirado")
    return claims


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print("uso: patch_secure.py [--naive] <token>", file=sys.stderr)
        return 20
    estricto = True
    if len(argv) == 3:
        if argv[1] != "--naive":
            print(f"argumento desconocido: {argv[1]}", file=sys.stderr)
            return 20
        estricto = False
    try:
        claims = verify_token(argv[-1], estricto=estricto)
    except InvalidToken as exc:
        print(f"DENEGADO: {exc}")
        return 1
    print(f"CONCEDIDO: {json.dumps(claims, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
