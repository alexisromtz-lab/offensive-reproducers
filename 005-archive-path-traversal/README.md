# 005 · escritura fuera del destino con el nombre del miembro (tar-slip)

invariante: estado
falsador: verifica

**Hipótesis.** Un extractor de archivos decide dónde escribe cada cosa **usando el nombre que el
archivo trae dentro**. Si nadie compara ese nombre con el destino, el archivo elige el destino.
Y esa decisión se toma en un solo punto —`os.path.join(destino, nombre)`— que casi nunca se mira.

Este laboratorio es **100 % sintético**: cinco archivos `.tar` construidos en memoria contra un
directorio temporal. Sin red, sin privilegios, sin dependencias fuera de la biblioteca estándar.

## Reproducción

```sh
python3 exploit_poc.py                                  # RC 0 · 5 de 5 vías
python3 exploit_poc.py --app patch_secure.py --naive    # RC 0 · 3 de 5 vías
python3 exploit_poc.py --app patch_secure.py            # RC 1 · 0 de 5 vías
```

Tarda menos de un segundo. Lo único que se escribe vive en `tempfile.mkdtemp(prefix="lab005-")`
y se borra al terminar; el marcador es un hecho del sistema de archivos —un fichero que existe
donde no debía, o uno que cambió de contenido—, no una salida de texto del programa.

## Las cinco vías

| # | nombre del miembro | capacidad que explota | parche ingenuo |
|---|---|---|---|
| 1 | `../FUERA-RELATIVA.txt` | el traversal de libro | **la cierra** |
| 2 | `/…/via02/FUERA-ABSOLUTA.txt` | un nombre absoluto ignora el destino | **la cierra** |
| 3 | `../lab005_eve/FUERA-HERMANA.txt` | **el prefijo de cadena no es un directorio** | entra |
| 4 | `enlace → ../lab005_eve` + `enlace/FUERA-ENLACE.txt` | un enlace simbólico mueve la escritura sin que el nombre que escribe tenga nada raro | entra |
| 5 | `config.json` (ya existía) | nadie pidió permiso para pisar | entra |

La vía 3 es el corazón de la cápsula. La comprobación ingenua es literalmente ésta:

```python
ruta = os.path.abspath(os.path.join(destino, nombre))
if not ruta.startswith(os.path.abspath(destino)):
    raise ArchivoRechazado(...)
```

y `"/tmp/x/lab005_eve/FUERA-HERMANA.txt".startswith("/tmp/x/lab005")` es **verdadero**. El destino
`lab005` y el hermano `lab005_eve` difieren en un guion bajo, y el prefijo no lo distingue. La
pregunta correcta no es «¿empieza por?» sino «¿el camino *relativo a* la raíz sale de la raíz?»,
y eso se contesta con componentes (`os.path.commonpath`), no con caracteres.

La vía 4 no es una variante de la 3: la 3 escapa con el nombre que se escribe, la 4 escapa con un
miembro **anterior** y escribe con un nombre perfectamente normal. Cerrar 1 y 2 no dice nada
sobre 4, y por eso el ingenuo la deja pasar.

## Anatomía

`app_vulnerable.extraer` confía en el archivo entero, que es lo que hace el código real:

```python
tar.extractall(destino)   # cada miembro decide su propia ruta
```

El `filter="fully_trusted"` explícito existe para que la cápsula se comporte igual en Python 3.9
y en 3.14+: desde 3.12 hay filtro, y desde 3.14 el defecto pasa a `data`, que rechazaría el
enlace de la vía 4 y convertiría un servicio vulnerable en uno que parece sano. Un sujeto que se
vuelve seguro por la versión del intérprete no es un sujeto que se arregló.

## Impacto

Escritura arbitraria con los permisos del proceso. En un servicio que descomprime lo que sube un
usuario, eso es ejecución de código por dos caminos conocidos: pisar un fichero que otro va a
ejecutar, o dejar caer una clave en `~/.ssh/authorized_keys` o un `.pth` en el directorio de
paquetes. La vía 4 añade el pivote: el enlace puede apuntar fuera del destino y el miembro que
escribe **parece** limpio en cualquier registro que sólo mire nombres.

## Remedio canónico

`patch_secure.py` valida **todos** los miembros antes de escribir el primer byte, y no escribe
ninguno si uno falla:

1. **Rechaza el nombre que no es un nombre**: NUL (`\x00`), ruta absoluta, componentes `..`.
2. **Rechaza el tipo que no es contenido**: `issym` e `islnk` fuera; sólo `isfile` e `isdir`
   entran. Sin enlaces no hay pivote.
3. **Pregunta por componentes**: `_dentro(raiz, os.path.realpath(os.path.join(raiz, nombre)))`
   con `os.path.commonpath`. `realpath` resuelve lo que ya exista en disco; `commonpath` compara
   directorios, no caracteres.
4. **No pisa nada**: si `os.path.lexists(objetivo)`, `ArchivoRechazado`. La sobreescritura no es
   un efecto secundario aceptable de extraer.
5. **Valida antes de escribir**: la lista se revisa completa primero. Un rechazo a mitad de
   extracción deja el destino en un estado que nadie pidió.

## Por qué el parche ingenuo también es un defecto medido

El ingenuo **sí** cierra las vías 1 y 2, y esa es exactamente la razón por la que se despliega:
pasa las pruebas que uno escribe después del incidente. Deja 3 de 5 abiertas porque la pregunta
que hace —prefijo de cadena— es sobre texto, no sobre el árbol de directorios.

El `CONTROL` de los tres comandos corre **antes** de las vías y prueba la no-vacuidad: un archivo
legítimo (`sub/informe.txt`) se extrae y su contenido se lee en los tres sujetos. Un parche que
se niega a extraer todo también daría `BLOQUEADO` en las cinco vías, y eso no es seguridad: es
un servicio roto.

El canónico, además, rechaza la **segunda** extracción del mismo archivo (decisión 4) mientras el
ingenuo y el vulnerable la aceptan. Está en `CONTROL` como fila propia porque es una diferencia
deliberada, no un efecto colateral: sobreescribir no es extraer.

## Alcance declarado

**No explorado a propósito:** los bits de modo del miembro (`TarInfo.mode`). Un miembro con modo
`0o4755` deja un binario con SUID **dentro** del destino: no escapa la frontera que esta cápsula
mide, y demostrarlo bien exige privilegios y un sistema de archivos que no monte `nosuid`. Queda
como cápsula propia, no como vía de ésta.

## Procedencia

Cápsula escrita desde cero para este repositorio. No reproduce ninguna sala, máquina ni reto de
ninguna plataforma: los archivos, el servicio y el ataque son de este archivo. La referencia
externa es la categoría pública **OWASP A01:2021 — Broken Access Control**, que en la edición de
2021 absorbe el recorrido de rutas y la autorización a nivel de objeto. Licencia MIT del
repositorio.
