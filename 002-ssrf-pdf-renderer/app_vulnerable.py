#!/usr/bin/env python3
"""Renderizador de URLs sin política de destino: la cápsula del SSRF.

HUELLA-OFFREP-002-APP-20261113

El fallo no está en la red, está en el diseño: `render()` recibe una URL del usuario y
la pide tal cual. No hay lista blanca, no hay resolución previa, no se comprueba el
destino y las redirecciones se siguen.

Consecuencia: todo lo alcanzable desde el proceso queda alcanzable desde el formulario.
En esta cápsula el «interior» es un servicio efímero en loopback; en un despliegue real
es el endpoint de metadatos del proveedor de nube, el panel de administración o la base
de datos interna.

    python3 app_vulnerable.py <url>     # pide la URL e imprime el cuerpo (RC 0)
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.parse
import urllib.request

TIEMPO_MAXIMO = 3.0
BYTES_MAXIMOS = 65536


class DestinoNoPermitido(Exception):
    """El destino de la URL no está permitido por la política del servicio."""


class FetchError(Exception):
    """El destino era alcanzable pero la petición no produjo un cuerpo."""


def destino_permitido(host: str, port: int, estricto: bool = True) -> bool:
    """Este servicio no tiene política de destino: cualquier host es aceptable."""
    return True


def render(url: str, estricto: bool = True) -> str:
    """Pide `url` y devuelve el cuerpo, sin validar el destino y siguiendo redirecciones."""
    partes = urllib.parse.urlsplit(url)
    if partes.scheme not in ("http", "https") or not partes.netloc:
        raise FetchError(f"URL no utilizable: {url!r}")
    pedido = urllib.request.Request(url, headers={"User-Agent": "render-lab-002"})
    try:
        with urllib.request.urlopen(pedido, timeout=TIEMPO_MAXIMO) as respuesta:
            return respuesta.read(BYTES_MAXIMOS).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code} en {url}") from exc
    except OSError as exc:
        raise FetchError(f"no se pudo alcanzar {url}: {exc}") from exc


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("uso: app_vulnerable.py <url>", file=sys.stderr)
        return 20
    try:
        cuerpo = render(argv[1])
    except (DestinoNoPermitido, FetchError) as exc:
        print(f"ERROR: {exc}")
        return 1
    print(cuerpo)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
