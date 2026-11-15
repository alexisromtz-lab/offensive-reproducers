"""Control de la regla «un rechazo tiene que estar declarado».

Declara los tres rechazos del dominio, pero REVIENTA con ValueError solo cuando el codigo
trae relleno -- el error interno de una rama de normalizacion sin implementar. Un PoC que
absorbiera `Exception` lo contaria como cupon cerrado y devolveria RC 1. El PoC solo absorbe
lo que el sujeto declara, asi que esto tiene que salir RC 3.
"""


class CuponInvalido(Exception):
    pass


class CuponAgotado(Exception):
    pass


class CompraInvalida(Exception):
    pass


CUPON = {"porcentaje": 50}
_USOS = {}


def canjear(usuario, codigo, compra_centavos, estricto=True):
    clave = codigo.strip().upper()
    if clave != "BIENVENIDA":
        raise CuponInvalido(codigo)
    if compra_centavos <= 0:
        raise CompraInvalida(compra_centavos)
    if len(codigo) != len(clave):
        raise ValueError("rama de normalizacion sin implementar")
    if _USOS.get((usuario, clave), 0) >= 1:
        raise CuponAgotado(usuario)
    _USOS[(usuario, clave)] = 1
    descuento = compra_centavos * CUPON["porcentaje"] // 100
    return {"descuento": descuento, "total": compra_centavos - descuento}
