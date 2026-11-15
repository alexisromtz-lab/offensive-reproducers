"""Control de la regla «una deduccion no es una apertura».

El sujeto registra las cuentas y despues niega toda credencial. Su barrido no abre nada
(`BLOQUEADA`) y su espacio sigue `CABE`: dos etiquetas que, leidas solas, absolverian a un
servicio que no autentica a nadie. El control legitimo es el que lo pone en RC 3.
"""

import hashlib

ALMACEN = {}


def registrar(usuario, clave, estricto=True):
    # Un digest de cuatro hex, igual que el vulnerable: lo unico que cambia es que abajo
    # no se autentica a nadie. El espacio tiene que seguir CABE para que el control muerda.
    ALMACEN[usuario] = hashlib.md5(clave.encode()).hexdigest()[:4]
    return ALMACEN[usuario]


def autenticar(usuario, clave_candidata, estricto=True):
    return False


def respaldo():
    return {usuario: {"sal": "", "digest": digest} for usuario, digest in ALMACEN.items()}
