#!/usr/bin/env python3
"""Sujeto que miente: hace el dano y despues declara el rechazo.

HUELLA-OFFREP-FALSADOR-20261117

Que pregunta
------------
Un PoC que solo mira la excepcion no distingue un parche que cierra de un parche que
**finge** cerrar. Este sujeto es lo segundo: por cada funcion que el PoC llama, primero
consulta a `patch_secure` --el testigo de «esta entrada se rechaza»-- y, si la entrada se
rechaza, ejecuta igual el codigo vulnerable y despues lanza la excepcion declarada.

    cd 010-serialization-validation-asymmetry
    python3 exploit_poc.py --app ../parche_mentiroso.py

La asimetria la usa el falsificador, no el PoC: el falsificador necesita saber cual es el
ataque, el PoC no. Aqui se importa `patch_secure` solo como testigo.

Como se lee
-----------
    RC 0   el PoC no se cree el rechazo: mira el estado y ve el efecto   (sano)
    RC 1   el PoC se cree el rechazo y publica BLOQUEADO                 (engañado)
    RC 3   el sujeto no carga: el PoC rompio por otra cosa

Un RC 1 con `[FALSADOR] rechazos fingidos=0` **no** es un veredicto: el falsificador no
llego a mentir y lo que se mide es su alcance, no el oraculo. Esa fila del censo se
publica NO_MEDIDO.

Alcance medido (2026-11-18, trece capsulas)
-------------------------------------------
`verifica`        005, 010, 011, 013, 014 · el PoC consulta el libro despues del rechazo
`engañado`        005, 008, 010  · antes del endurecimiento de 005 y 010; hoy ninguno
`fuera de alcance` 001, 002, 006, 007, 008 · el efecto **es** el valor de retorno que el
                  falsificador descarta al lanzar: no hay estado que mirar, ni sano ni
                  engañado. No es una tarea pendiente, es una frontera del instrumento.
`NO_MEDIDO`       003  · el testigo no declaro rechazo que falsificar (0 fingidos)
`ROTO`            004  · el falsificador altera el sujeto hasta romperlo (RC 3)
`cuelga`          009  · el falsificador no termina sobre ese sujeto

Sin red, sin dependencias externas, sobre el directorio de la capsula.
"""
from __future__ import annotations

import importlib
import os
import sys
import types

sys.path.insert(0, os.getcwd())

_fix = importlib.import_module("patch_secure")
_ruta = os.path.join(os.getcwd(), "app_vulnerable.py")
exec(compile(open(_ruta, encoding="utf-8").read(), _ruta, "exec"), globals())

NO_MEDIDO: list[str] = []
FINGIDOS: list[str] = []


def _declarada(exc: BaseException) -> BaseException | None:
    """La excepcion del testigo traducida a la clase que declara el sujeto."""
    cls = globals().get(type(exc).__name__)
    if isinstance(cls, type) and issubclass(cls, BaseException):
        try:
            return cls(str(exc))
        except Exception:
            return exc
    return None


def _envolver(nombre: str, propia, testigo) -> types.FunctionType:
    def mentiroso(*a, **k):
        try:
            testigo(*a, **k)
        except Exception as exc:
            traducida = _declarada(exc)
            if traducida is None:
                # El sujeto no declara esa excepcion: no hay mentira que fabricar.
                NO_MEDIDO.append(f"{nombre}: {type(exc).__name__} no declarada")
                return propia(*a, **k)
            propia(*a, **k)          # el dano ocurre...
            FINGIDOS.append(nombre)
            raise traducida          # ...y despues se anuncia el rechazo
        return propia(*a, **k)

    mentiroso.__name__ = nombre
    return mentiroso


# `isinstance(x, types.FunctionType)` y no `callable(x)`: las clases de excepcion tambien
# son callable, y envolverlas rompe el `except` del PoC. `__module__` tampoco sirve: el
# sujeto exec'd hereda este modulo.
for _n in sorted(dir(_fix)):
    _t = getattr(_fix, _n)
    _p = globals().get(_n)
    if (_n.startswith("_") or _n in {"main", "NO_MEDIDO", "FINGIDOS"}
            or not isinstance(_t, types.FunctionType)
            or not isinstance(_p, types.FunctionType)):
        continue
    globals()[_n] = _envolver(_n, _p, _t)


import atexit


@atexit.register
def _resumen() -> None:
    print("[FALSADOR] rechazos fingidos=" + str(len(FINGIDOS)) + " " + repr(FINGIDOS),
          file=sys.stderr)
    if NO_MEDIDO:
        print("[FALSADOR NO MEDIDO] " + "; ".join(NO_MEDIDO), file=sys.stderr)
