#!/usr/bin/env python3
"""Renderizador de URLs con política de destino: el parche canónico y el parche ingenuo.

HUELLA-OFFREP-002-PARCHE-20261113

Qué cambia
----------
El destino deja de ser una cadena y pasa a ser un conjunto de direcciones resueltas:

  1. se resuelve el nombre una sola vez con `socket.getaddrinfo`;
  2. se exige que TODAS las direcciones devueltas sean globales (`ipaddress.is_global`),
     porque un mismo nombre puede devolver una dirección pública y una interna;
  3. se conecta a la dirección ya validada y no al nombre, para que el DNS no pueda
     cambiar entre la comprobación y el uso (rebinding);
  4. las redirecciones no se siguen: un 3xx es un destino nuevo y hay que validarlo,
     porque el salto ya validado no dice nada del salto siguiente.

El modo ingenuo
---------------
`render(url, estricto=False)` reproduce el primer parche que aparece en la práctica: una
lista negra de texto («localhost», «127.») aplicada al host de la URL de entrada. Cierra
el caso evidente y deja abiertas las puertas que el PoC usa: la misma dirección escrita
de otra forma —decimal `2130706433`, hexadecimal `0x7f000001`, IPv4 mapeada en IPv6— y
la redirección, cuyo salto final nunca se vuelve a mirar. Se incluye a propósito: un
parche que no se puede refutar con el mismo PoC no está demostrado.

    python3 exploit_poc.py --app patch_secure.py --naive   # RC 0: sigue entrando
    python3 exploit_poc.py --app patch_secure.py           # RC 1: bloqueado
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

TIEMPO_MAXIMO = 3.0
BYTES_MAXIMOS = 65536

# Lista negra del parche ingenuo: compara texto, no direcciones.
NOMBRES_BLOQUEADOS = frozenset({"localhost"})
PREFIJOS_BLOQUEADOS = ("127.",)


class DestinoNoPermitido(Exception):
    """El destino de la URL no está permitido por la política del servicio."""


class FetchError(Exception):
    """El destino era alcanzable pero la petición no produjo un cuerpo."""


def _nombre(host: str) -> str:
    return host.strip("[]").strip().lower()


def _resolver(host: str, port: int) -> list[str]:
    """Direcciones del nombre, sin repetir. Un solo getaddrinfo por decisión."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({info[4][0].split("%")[0] for info in infos})


def destino_permitido(host: str, port: int, estricto: bool = True) -> bool:
    """Política de destino, pura respecto de la red una vez resuelto el nombre."""
    nombre = _nombre(host)
    if not estricto:
        if nombre in NOMBRES_BLOQUEADOS:
            return False
        return not any(nombre.startswith(prefijo) for prefijo in PREFIJOS_BLOQUEADOS)
    try:
        direcciones = _resolver(nombre, port)
    except (socket.gaierror, UnicodeError):
        return False
    if not direcciones:
        return False
    return all(ipaddress.ip_address(direccion).is_global for direccion in direcciones)


def render(url: str, estricto: bool = True) -> str:
    """Pide `url` si su destino pasa la política, y devuelve el cuerpo."""
    partes = urllib.parse.urlsplit(url)
    if partes.scheme not in ("http", "https") or not partes.hostname:
        raise FetchError(f"URL no utilizable: {url!r}")
    try:
        puerto = partes.port or (443 if partes.scheme == "https" else 80)
    except ValueError as exc:
        raise FetchError(f"puerto no utilizable en {url!r}: {exc}") from exc
    nombre = _nombre(partes.hostname)

    if not estricto:
        if not destino_permitido(nombre, puerto, estricto=False):
            raise DestinoNoPermitido(f"destino no permitido: {nombre}:{puerto}")
        return _pedir_siguiendo_redirecciones(url)

    direcciones = _resolver_seguro(nombre, puerto)
    for direccion in direcciones:
        if not ipaddress.ip_address(direccion).is_global:
            raise DestinoNoPermitido(
                f"{nombre} resuelve a {direccion}, que no es una direccion global")
    return _pedir_fijado(direcciones[0], puerto, partes)


def _resolver_seguro(nombre: str, puerto: int) -> list[str]:
    try:
        direcciones = _resolver(nombre, puerto)
    except (socket.gaierror, UnicodeError) as exc:
        raise FetchError(f"no se pudo resolver {nombre!r}: {exc}") from exc
    if not direcciones:
        raise DestinoNoPermitido(f"{nombre} no resuelve a ninguna direccion")
    return direcciones


def _pedir_siguiendo_redirecciones(url: str) -> str:
    """Camino del parche ingenuo: valida la entrada y deja que urllib siga los 3xx."""
    pedido = urllib.request.Request(url, headers={"User-Agent": "render-lab-002"})
    try:
        with urllib.request.urlopen(pedido, timeout=TIEMPO_MAXIMO) as respuesta:
            return respuesta.read(BYTES_MAXIMOS).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code} en {url}") from exc
    except OSError as exc:
        raise FetchError(f"no se pudo alcanzar {url}: {exc}") from exc


def _pedir_fijado(direccion: str, puerto: int, partes: urllib.parse.SplitResult) -> str:
    """Conecta a la dirección ya validada; el nombre no se vuelve a resolver."""
    ruta = partes.path or "/"
    if partes.query:
        ruta = f"{ruta}?{partes.query}"
    cabecera_host = partes.netloc.rsplit("@", 1)[-1]
    conexion = http.client.HTTPConnection(direccion, puerto, timeout=TIEMPO_MAXIMO)
    try:
        conexion.request("GET", ruta, headers={"Host": cabecera_host,
                                               "User-Agent": "render-lab-002"})
        respuesta = conexion.getresponse()
        if 300 <= respuesta.status < 400:
            destino = respuesta.getheader("Location")
            raise DestinoNoPermitido(
                f"redireccion no seguida (HTTP {respuesta.status}) hacia {destino!r}:"
                " un 3xx es un destino nuevo y hay que validarlo")
        if respuesta.status >= 400:
            raise FetchError(f"HTTP {respuesta.status} en {ruta}")
        return respuesta.read(BYTES_MAXIMOS).decode("utf-8", "replace")
    except OSError as exc:
        raise FetchError(f"no se pudo alcanzar {direccion}:{puerto}: {exc}") from exc
    finally:
        conexion.close()


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print("uso: patch_secure.py [--naive] <url>", file=sys.stderr)
        return 20
    estricto = True
    if len(argv) == 3:
        if argv[1] != "--naive":
            print(f"argumento desconocido: {argv[1]}", file=sys.stderr)
            return 20
        estricto = False
    try:
        cuerpo = render(argv[-1], estricto=estricto)
    except DestinoNoPermitido as exc:
        print(f"DENEGADO: {exc}")
        return 1
    except FetchError as exc:
        print(f"ERROR: {exc}")
        return 1
    print(cuerpo)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
