#!/usr/bin/env python3
"""Inyector de reloj: mueve el instante sin tocar una linea del sujeto.

HUELLA-OFFREP-RELOJ-20261117

Que hace
--------
El gate lo copia a una jaula como `sitecustomize.py` y pone la jaula en `PYTHONPATH`; ahi
Python lo importa al arrancar y, si `AHORA` esta definida, `time.time()` y
`datetime.datetime.now()` devuelven ese instante en vez del reloj real. El sujeto pregunta
la hora por el mismo camino de siempre: no sabe que lo estan midiendo y no se le cambia
nada.

Que NO hace
-----------
No es un mock de reloj: no detiene el tiempo ni lo acelera. Solo sustituye la respuesta de
las dos vias estandar de Python 3. Un sujeto que lea la hora por una extension en C, por
`os.clock()` o por un servicio externo no se mueve con esto, y esa frontera se declara en
el README en vez de fingir que se mide.
"""

import datetime as _dt
import os
import time as _time

if "AHORA" in os.environ:
    _instante = float(os.environ["AHORA"])
    _time.time = lambda: _instante

    class _RelojFijo(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(_instante, tz)

        @classmethod
        def utcnow(cls):
            return cls.utcfromtimestamp(_instante)

    _dt.datetime = _RelojFijo
