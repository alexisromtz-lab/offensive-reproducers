# 004 · autorización a nivel de objeto (IDOR)

**Hipótesis.** Un servicio puede autenticar correctamente y aun así no autorizar nada. Si el
código resuelve la sesión y después devuelve el objeto que la ruta nombra, el identificador se
convierte en la credencial: quien lo conozca, entra.

Este laboratorio es **100 % sintético**: dos inquilinos (`norte`, `sur`), dos personas con el
mismo nombre en cada uno (`ana`, `beto`) y cuatro expedientes en memoria. Sin red, sin disco,
sin dependencias fuera de la biblioteca estándar.

## Reproducción

```sh
python3 exploit_poc.py                                  # RC 0 · 5 de 5 vías
python3 exploit_poc.py --app patch_secure.py --naive    # RC 0 · 4 de 5 vías
python3 exploit_poc.py --app patch_secure.py            # RC 1 · 0 de 5 vías
```

Tarda menos de un segundo. Los tres comandos corren en el mismo proceso y no escriben nada
fuera de la memoria del intérprete.

## Las cinco vías

La sesión del ataque es siempre `ana@norte`, legítima y recién emitida. Ninguna vía adivina un
token: el token se pide por la puerta del propio servicio.

| # | petición | decisión que falta | parche ingenuo |
|---|---|---|---|
| 1 | `GET /objetos/2` | comparar el objeto con la sesión | **la cierra** |
| 2 | `GET /objetos/1001` | comparar el **inquilino**, no sólo el nombre del dueño | entra |
| 3 | `GET /objetos?dueno=beto` | no dejar que el cliente elija el sujeto del filtro | entra |
| 4 | `GET /objetos/2` + `X-Usuario: beto` | que la identidad la fije el token, no la cabecera | entra |
| 5 | `PATCH /objetos/2` | aplicar el mismo predicado a la escritura | entra |

La vía 2 es la que más se repite en producción y la que peor se ve en revisión: el predicado
`objeto.dueno == sesion.usuario` **parece** una comprobación de propiedad y es verdadera para
`ana` del sur cuando pregunta `ana` del norte. El nombre no es un ámbito.

## Anatomía

`app_vulnerable.atender` decide en tres tramos y **ninguno** compara con la sesión:

```python
sesion_de(token)  # se resuelve la sesión… y no se vuelve a usar
if metodo == "GET" and ruta.startswith("/objetos/"):
    return dict(_objeto(ruta.rsplit("/", 1)[1]))   # cero predicado
```

La autenticación está. La autorización no existe: no hay una línea que pregunte *¿este objeto es
de quien pregunta?*. Y como tampoco hay un índice particionado por inquilino, el identificador
ajeno es direccionable.

## Impacto

Lectura y **escritura** de expedientes de otras personas y de otros inquilinos, sin más
credencial que una sesión propia y un número. Enumerar identificadores contiguos convierte el
fallo en una exportación completa. En un inquilino compartido, la vía 2 cruza la frontera que
separa dos clientes: es el incidente que se notifica, no el que se documenta.

## Remedio canónico

`patch_secure.py` cambia cinco decisiones, no cinco líneas:

1. **Un predicado, una puerta.** `puede(sesion, objeto)` exige inquilino **y** dueño, y se
   evalúa antes de mirar la ruta. Toda ruta nueva hereda la comprobación por construcción.
2. **El sujeto lo nombra el token.** El token va firmado con HMAC-SHA256 y se verifica con
   `hmac.compare_digest` antes de interpretar el cuerpo. `usuario_efectivo` ignora `X-Usuario`.
3. **Índice particionado.** `_del_inquilino` busca en el ámbito del inquilino de la sesión: un
   identificador ajeno devuelve `NoEncontrado`, no un objeto.
4. **El cliente no elige el sujeto del filtro.** `?dueno=` sólo puede nombrar a la propia
   sesión; cualquier otro valor es `NoAutorizado`.
5. **La escritura pasa por la misma puerta** y por una lista blanca de campos (`titulo`).

## Por qué el parche ingenuo también es un defecto medido

El ingenuo cierra la vía 1 y **rompe tráfico legítimo**: con la cabecera `X-Usuario: beto`, `ana`
deja de poder leer *su propio* expediente, porque el ingenuo le pregunta a la cabecera quién es.
Un filtro que niega al dueño su propio objeto no es un parche a medias: es un segundo defecto.

Eso se ve en la sección `CONTROL` de los tres comandos, que corre **antes** de las vías para que
la vía 5 no ensucie la lectura.

## Procedencia

Cápsula escrita desde cero para este repositorio. No reproduce ninguna sala, máquina ni reto de
ninguna plataforma: el servicio, los datos y el ataque son de este archivo. Licencia MIT del
repositorio.
