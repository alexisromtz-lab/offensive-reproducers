#!/usr/bin/env python3
"""El mismo canje, en dos versiones.

HUELLA-OFFREP-008-PARCHE-20261115

    python3 patch_secure.py --cupon BIENVENIDA --compra 100000   # canonico
    python3 patch_secure.py --naive --cupon ...                  # el que cierra el caso reportado

Canonico
--------
El uso del cupón es parte del sujeto, no del catálogo: un registro por `(cuenta, código
normalizado)` que se consulta y se escribe **después de normalizar**, y un importe que
tiene que ser positivo para ser un importe. La normalización es una sola en todo el
servicio: la misma cadena que se usa para buscar es la que se usa para contar.

Ingenuo
-------
Arregla **el caso que se reportó**: «la misma cuenta reutiliza su cupón de bienvenida».
Añade un registro de usos… con la clave tal como llegó del cliente, mientras la búsqueda
del cupón sí normaliza. Buscar normalizando y contar sin normalizar deja dos nombres para
el mismo cupón: `"BIENVENIDA"` cuenta como usado y `" Bienvenida "` no. El registro existe
y no registra.
"""

from __future__ import annotations

import argparse
import json
import sys

CUPONES: dict[str, dict[str, int]] = {
    "BIENVENIDA": {"porcentaje": 50, "usos_por_cuenta": 1},
    "TEMPORADA": {"porcentaje": 10, "usos_por_cuenta": 3},
}


class CuponInvalido(Exception):
    """El código no corresponde a ningún cupón del catálogo."""


class CuponAgotado(Exception):
    """La cuenta ya consumió los usos que el cupón declara."""


class CompraInvalida(Exception):
    """El importe de la compra no es un importe."""


def _normalizar(codigo: str) -> str:
    return codigo.strip().upper()


_USOS_INGENUO: dict[tuple[str, str], int] = {}
_USOS_CANONICO: dict[tuple[str, str], int] = {}


def _canjear_ingenuo(usuario: str, codigo: str, compra_centavos: int) -> dict[str, int]:
    clave = _normalizar(codigo)
    cupon = CUPONES.get(clave)
    if cupon is None:
        raise CuponInvalido(f"no existe el cupon {codigo!r}")

    # La misma cuenta ya usó este cupón… si lo tecleó igual que la primera vez.
    usos = _USOS_INGENUO.get((usuario, codigo), 0)
    if usos >= cupon["usos_por_cuenta"]:
        raise CuponAgotado(f"{usuario} ya uso {clave}")
    _USOS_INGENUO[(usuario, codigo)] = usos + 1

    descuento = compra_centavos * cupon["porcentaje"] // 100
    return {
        "compra": compra_centavos,
        "descuento": descuento,
        "total": compra_centavos - descuento,
        "porcentaje": cupon["porcentaje"],
    }


def _canjear_canonico(usuario: str, codigo: str, compra_centavos: int) -> dict[str, int]:
    clave = _normalizar(codigo)
    cupon = CUPONES.get(clave)
    if cupon is None:
        raise CuponInvalido(f"no existe el cupon {codigo!r}")
    if compra_centavos <= 0:
        raise CompraInvalida(f"importe no positivo: {compra_centavos}")

    usos = _USOS_CANONICO.get((usuario, clave), 0)
    if usos >= cupon["usos_por_cuenta"]:
        raise CuponAgotado(f"{usuario} ya uso {clave}")
    # Se anota antes de conceder: un fallo al cobrar no devuelve el uso.
    _USOS_CANONICO[(usuario, clave)] = usos + 1

    descuento = compra_centavos * cupon["porcentaje"] // 100
    return {
        "compra": compra_centavos,
        "descuento": descuento,
        "total": compra_centavos - descuento,
        "porcentaje": cupon["porcentaje"],
    }


def canjear(usuario: str, codigo: str, compra_centavos: int, estricto: bool = True) -> dict[str, int]:
    if estricto:
        return _canjear_canonico(usuario, codigo, compra_centavos)
    return _canjear_ingenuo(usuario, codigo, compra_centavos)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cupones con la regla de uso aplicada.")
    parser.add_argument("--cupon", required=True)
    parser.add_argument("--compra", required=True, type=int, help="importe en centavos")
    parser.add_argument("--usuario", default="ana")
    parser.add_argument("--naive", action="store_true", help="modo ingenuo")
    args = parser.parse_args(argv)

    try:
        print(json.dumps(canjear(args.usuario, args.cupon, args.compra, estricto=not args.naive),
                         sort_keys=True))
    except (CuponInvalido, CuponAgotado, CompraInvalida) as exc:
        print(f"RECHAZADO: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
