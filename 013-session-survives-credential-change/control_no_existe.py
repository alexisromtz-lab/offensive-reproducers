"""Control de la regla «un servicio que no autentica no puede absolverse por no dejar nada vivo».

El sujeto rechaza toda credencial y todo cambio. Sus dos vias salen `NO EJERCIDA`, que leidas
solas absolverian a un servicio que no hace nada: no quedo ninguna sesion viva porque no se abrio
ninguna. El control legitimo —la credencial nueva entra, la vieja no, una sesion abierta despues
del cambio autoriza y una concesion posterior refresca— es el que lo pone en RC 3.

Sin este control, la capsula premiaria con RC 1 al sistema mas seguro de todos: el apagado. Para
A07 el falso verde tiene esa forma exacta, porque «no hay sesiones vivas» se lee como «no hay
sesiones que revocar».
"""

from __future__ import annotations

from typing import Any


class Rechazo(ValueError):
    """Rechazo declarado: ninguna credencial se admite, por politica."""


def reiniciar() -> None:
    return None


def entrar(usuario: str, clave: str) -> str:
    _ = (usuario, clave)
    raise Rechazo("credencial invalida")


def abrir_persistente(usuario: str, clave: str) -> str:
    _ = (usuario, clave)
    raise Rechazo("credencial invalida")


def solicitar(usuario: str) -> str:
    _ = usuario
    raise Rechazo("usuario desconocido")


def restablecer(token: str, clave_nueva: str, estricto: bool = True) -> dict[str, Any]:
    _ = (token, clave_nueva, estricto)
    raise Rechazo("token desconocido")


def autorizar(sid: str, estricto: bool = True) -> dict[str, Any]:
    _ = (sid, estricto)
    raise Rechazo("sesion desconocida")


def refrescar(concesion: str, estricto: bool = True) -> str:
    _ = (concesion, estricto)
    raise Rechazo("concesion desconocida")


def sesion_vigente(sid: str, estricto: bool = True) -> bool:
    _ = (sid, estricto)
    return False


def concesion_vigente(concesion: str, estricto: bool = True) -> bool:
    _ = (concesion, estricto)
    return False


def credencial_vigente(usuario: str) -> str:
    _ = usuario
    return ""
