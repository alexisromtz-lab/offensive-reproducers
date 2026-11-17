# 002 · SSRF en el renderizador de URLs

invariante: retorno
falsador: fuera-de-alcance

Un servicio genera previsualizaciones: recibe una URL y la pide. No comprueba el destino,
así que también pide las direcciones que sólo el servidor puede alcanzar. En esta cápsula
el «interior» es un servicio efímero en loopback; en un despliegue real es el endpoint de
metadatos del proveedor de nube, el panel de administración o la base de datos interna.

- [app_vulnerable.py](app_vulnerable.py) — el renderizador sin política de destino.
- [exploit_poc.py](exploit_poc.py) — levanta el interior y lo alcanza por cinco vías; decide por código de salida.
- [patch_secure.py](patch_secure.py) — resolución, `is_global`, conexión fijada y cero redirecciones; incluye el modo ingenuo.

## Reproducir en menos de 10 segundos

```bash
git clone --depth 1 https://github.com/alexisromtz-lab/offensive-reproducers
cd offensive-reproducers/002-ssrf-pdf-renderer

python3 exploit_poc.py                                  # RC 0  · EXPLOTADO (5 de 5 vías)
python3 exploit_poc.py --app patch_secure.py --naive    # RC 0  · el parche ingenuo no basta (4 de 5)
python3 exploit_poc.py --app patch_secure.py            # RC 1  · BLOQUEADO (0 de 5)
```

Sin dependencias: sólo la biblioteca estándar de Python 3.9 o superior. Sin red externa:
los dos servicios que el PoC necesita viven en el mismo proceso, en loopback y en puertos
efímeros, y mueren al terminar la corrida.

## Hipótesis

> Si el renderizador acepta una URL del usuario y la pide sin validar la dirección de
> destino, entonces cualquier servicio alcanzable desde el proceso es alcanzable desde el
> formulario, y la comprobación del host sólo vale si se hace sobre direcciones resueltas
> y en cada salto.

El PoC la falsa en tres sujetos distintos con el mismo comando. La tercera corrida —el
parche canónico— devuelve RC 1: ahí la hipótesis deja de sostenerse y por eso el parche
está demostrado.

## Las cinco vías

| vía | qué demuestra |
|-----|---------------|
| `http://127.0.0.1:PUERTO/interno/secreto` | control negativo: si un parche no cierra esta, no es un parche |
| `http://2130706433:PUERTO/...` | la misma dirección en decimal: un filtro de texto no ve `127.` |
| `http://0x7f000001:PUERTO/...` | la misma dirección en hexadecimal |
| `http://[::ffff:127.0.0.1]:PUERTO/...` | la misma dirección mapeada en IPv6 |
| `.../redirige` → 302 | el primer salto pasa el filtro y el salto final —un `127.0.0.1` literal— no lo mira nadie |

La quinta vía es la que no se arregla mirando mejor la URL de entrada: el filtro corre una
sola vez, en la puerta, y una redirección es una segunda puerta. Por eso el parche canónico
no sigue los `3xx`: los convierte en un destino nuevo que hay que validar.

## Anatomía del fallo

Dos decisiones independientes, inocentes cada una por separado:

1. **La URL del usuario es la URL de la petición.** El renderizador no distingue «lo que
   el cliente quiere ver» de «lo que el servidor puede alcanzar». Son dos espacios
   distintos y el código los trata como uno.
2. **El destino se decide comparando texto.** `localhost` y `127.` son dos maneras de
   escribir una dirección entre muchas. `2130706433`, `0x7f000001` y `[::ffff:127.0.0.1]`
   son la misma dirección y ninguna de las tres empieza por `127.`.

Juntas producen el efecto: el filtro rechaza la forma que el autor tenía en la cabeza y
acepta todas las demás. La redirección añade el tercer caso: aunque el filtro fuese
perfecto sobre la entrada, el salto siguiente se pide sin volver a preguntar.

## Impacto

Lectura de servicios internos con las credenciales del propio servidor: metadatos de la
nube (que suelen incluir credenciales temporales), APIs de administración sin autenticación
por estar en la red interna, y enumeración de puertos por tiempo de respuesta. El atacante
no necesita acceso a la red interna: necesita que el servidor tenga acceso y le haga el
trabajo.

## Remedio canónico

En [patch_secure.py](patch_secure.py), el destino deja de ser una cadena y pasa a ser un
conjunto de direcciones resueltas una sola vez:

```python
direcciones = _resolver(nombre, puerto)
for direccion in direcciones:
    if not ipaddress.ip_address(direccion).is_global:
        raise DestinoNoPermitido(f"{nombre} resuelve a {direccion}, que no es global")
return _pedir_fijado(direcciones[0], puerto, partes)
```

Cuatro decisiones, y ninguna sobra:

- **Resolver antes de decidir**, porque el espacio de nombres es del atacante y el de
  direcciones no.
- **Exigir que todas las direcciones sean globales**, no sólo la primera: un nombre puede
  devolver una pública y una interna.
- **Conectar a la dirección validada y no al nombre**, para que el DNS no cambie entre la
  comprobación y el uso (rebinding). La cabecera `Host` conserva el nombre original.
- **No seguir redirecciones**: un `3xx` es un destino nuevo.

Con `estricto=False` el parche sólo aplica la lista negra de texto y el PoC vuelve a entrar
por cuatro de las cinco vías. Ese modo está incluido a propósito: un parche que no se puede
refutar con el mismo PoC no está demostrado.

`destino_permitido("93.184.216.34", 443)` sigue devolviendo `True` en los dos parches: el
canónico no es una denegación en bloque, es una política sobre direcciones.

## Procedencia

Material propio. Este repositorio no contiene material de ninguna plataforma de
entrenamiento: ni salas, ni banderas, ni recorridos, ni capturas. El servicio interior, el
servicio público, el renderizador, el exploit y el parche se escribieron desde cero para
esta cápsula, y ninguno de los dos servicios escucha fuera de `127.0.0.1`. La referencia
externa es la categoría pública **OWASP A10:2021 — Server-Side Request Forgery (SSRF)**.
