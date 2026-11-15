#!/usr/bin/env python3
"""Servicio mínimo de cupones: el uso del cupón no forma parte del diseño.

HUELLA-OFFREP-008-APP-20261115

Qué modela
----------
Un comercio con un cupón de bienvenida declarado **de un solo uso por cuenta**. `canjear`
resuelve el cupón, calcula el descuento y devuelve el importe a cobrar.

Lo que falta no es una línea mal escrita: es una decisión que nadie tomó. El servicio
declara `usos_por_cuenta: 1` en el catálogo y **nunca cuenta los usos**, así que la regla
existe sólo como texto. Y acepta cualquier importe de compra, incluidos los negativos.

    python3 app_vulnerable.py --cupon BIENVENIDA --compra 100000

Códigos
-------
0   la compra se atendió
1   la compra fue rechazada
20  argumentos incompatibles
"""

from __future__ import annotations

import argparse
import json
import sys

# El catálogo declara la regla. Nadie la hace cumplir.
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
    """El código tal como lo teclea una persona: con espacios y en cualquier caja."""
    return codigo.strip().upper()


def canjear(usuario: str, codigo: str, compra_centavos: int, estricto: bool = True) -> dict[str, int]:
    """Atiende un canje y devuelve el importe a cobrar, en centavos."""
    clave = _normalizar(codigo)
    cupon = CUPONES.get(clave)
    if cupon is None:
        raise CuponInvalido(f"no existe el cupon {codigo!r}")

    descuento = compra_centavos * cupon["porcentaje"] // 100
    return {
        "compra": compra_centavos,
        "descuento": descuento,
        "total": compra_centavos - descuento,
        "porcentaje": cupon["porcentaje"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cupones con la regla de uso solo en el catalogo.")
    parser.add_argument("--cupon", required=True)
    parser.add_argument("--compra", required=True, type=int, help="importe en centavos")
    parser.add_argument("--usuario", default="ana")
    args = parser.parse_args(argv)

    try:
        print(json.dumps(canjear(args.usuario, args.cupon, args.compra), sort_keys=True))
    except (CuponInvalido, CuponAgotado, CompraInvalida) as exc:
        print(f"RECHAZADO: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
