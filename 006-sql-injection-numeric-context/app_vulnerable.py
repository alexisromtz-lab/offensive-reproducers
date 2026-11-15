#!/usr/bin/env python3
"""Sujeto vulnerable: consulta de una cuenta por id en un contexto NUMERICO.

HUELLA-OFFREP-006-APP-20261114

El sujeto tiene una sola operacion: devolver la cuenta `id` si la clave la acompana.
El id es un entero, asi que el codigo no lo entrecomilla — para que, si un entero no
lleva comillas. Esa decision es el fallo entero: `id = {entrada}` se concatena crudo.

Solo biblioteca estandar: `sqlite3` sobre `:memory:`. Sin red, sin ficheros, sin estado.
"""

from __future__ import annotations

import argparse
import sqlite3

SENTINELA = "SENTINELA-SQLI-006"

FILAS = (
    (1, "ana", "clave-ana", "PUBLICA"),
    (7, "root", "clave-root", SENTINELA),
)


def conexion() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE cuentas (id INTEGER PRIMARY KEY, usuario TEXT, clave TEXT, marca TEXT)")
    con.executemany("INSERT INTO cuentas (id, usuario, clave, marca) VALUES (?, ?, ?, ?)", FILAS)
    return con


def consultar(entrada_id: str, clave: str, **_ignorados: object) -> list[tuple[str, str]]:
    """Devuelve (usuario, marca) de esa cuenta si la clave coincide."""
    sql = f"SELECT usuario, marca FROM cuentas WHERE id = {entrada_id} AND clave = '{clave}'"
    with conexion() as con:
        return [tuple(fila) for fila in con.execute(sql)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Consulta de cuenta (vulnerable).")
    parser.add_argument("--id", required=True)
    parser.add_argument("--clave", required=True)
    args = parser.parse_args(argv)
    for usuario, marca in consultar(args.id, args.clave):
        print(f"{usuario}\t{marca}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
