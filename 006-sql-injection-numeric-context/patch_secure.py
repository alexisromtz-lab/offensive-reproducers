#!/usr/bin/env python3
"""El mismo sujeto, en dos versiones.

HUELLA-OFFREP-006-PARCHE-20261114

    python3 patch_secure.py --id 7 --clave clave-root    # canonico
    python3 patch_secure.py --naive ...                  # el que cierra el caso reportado

Canonico
--------
La entrada deja de ser SQL. `id = ?` recibe el valor como parametro: el motor lo trata
como dato y no como texto a interpretar, asi que el texto no hay que filtrarlo, ni
escaparlo, ni adivinarlo. La clave viaja igual. No queda lista negra que mantener ni
transformacion que deshacer.

Ingenuo
-------
Arregla **el vector que se reporto**: rechaza `" or "` y `"--"`, que es literalmente el
ataque del informe, y escapa las comillas de la clave —que ya se escapaban, porque el
problema no estaba ahi, sino en el entero sin comillas—. El ataque sigue vivo con
espacios de otra clase: en SQLite `/**/` separa tokens igual que un espacio, y
`0/**/or/**/1=1/**/or/**/1=1` no contiene ni `" or "` ni `"--"`.

Una lista negra enumera grafias. El lenguaje tiene mas grafias que la lista.
"""

from __future__ import annotations

import argparse
import sqlite3

SENTINELA = "SENTINELA-SQLI-006"

FILAS = (
    (1, "ana", "clave-ana", "PUBLICA"),
    (7, "root", "clave-root", SENTINELA),
)

FRAGMENTOS_PROHIBIDOS = (" or ", "--")


class ConsultaRechazada(Exception):
    """La entrada no pasa la lista negra del parche ingenuo."""


def conexion() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE cuentas (id INTEGER PRIMARY KEY, usuario TEXT, clave TEXT, marca TEXT)")
    con.executemany("INSERT INTO cuentas (id, usuario, clave, marca) VALUES (?, ?, ?, ?)", FILAS)
    return con


def _consultar_ingenuo(entrada_id: str, clave: str) -> list[tuple[str, str]]:
    minusculas = entrada_id.lower()
    for fragmento in FRAGMENTOS_PROHIBIDOS:
        if fragmento in minusculas:
            raise ConsultaRechazada(f"entrada rechazada: contiene {fragmento!r}")
    clave_escapada = clave.replace("'", "''")
    sql = f"SELECT usuario, marca FROM cuentas WHERE id = {entrada_id} AND clave = '{clave_escapada}'"
    with conexion() as con:
        return [tuple(fila) for fila in con.execute(sql)]


def _consultar_canonico(entrada_id: str, clave: str) -> list[tuple[str, str]]:
    sql = "SELECT usuario, marca FROM cuentas WHERE id = ? AND clave = ?"
    with conexion() as con:
        return [tuple(fila) for fila in con.execute(sql, (entrada_id, clave))]


def consultar(entrada_id: str, clave: str, estricto: bool = True) -> list[tuple[str, str]]:
    if estricto:
        return _consultar_canonico(entrada_id, clave)
    return _consultar_ingenuo(entrada_id, clave)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Consulta de cuenta (parcheada).")
    parser.add_argument("--id", required=True)
    parser.add_argument("--clave", required=True)
    parser.add_argument("--naive", action="store_true", help="modo ingenuo")
    args = parser.parse_args(argv)
    try:
        filas = consultar(args.id, args.clave, estricto=not args.naive)
    except ConsultaRechazada as exc:
        print(f"RECHAZADO: {exc}")
        return 1
    for usuario, marca in filas:
        print(f"{usuario}\t{marca}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
