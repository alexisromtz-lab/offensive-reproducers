"""Sujeto de control: falla siempre, y ninguna capsula puede absolverlo.

HUELLA-OFFREP-SUJETO-ROTO-20261115

Lo usa el bucle de `README.md` como tercer modo: un sujeto que no funciona debe salir
con RC 3, nunca con RC 1. Sin esta comprobacion, una capsula que lea cualquier excepcion
como "bloqueado" declara correcto a un sujeto que no responde a nada.
"""


def __getattr__(nombre: str):
    def _cualquiera(*args, **kwargs):
        raise RuntimeError("sujeto de control: este sujeto falla siempre")

    return _cualquiera
