# 013 · La credencial cambia y lo que la credencial vieja ya había emitido sigue entrando

invariante: estado
falsador: verifica

Una tienda cambia la contraseña de una cuenta y **lo hace bien**: la contraseña vieja deja de
entrar, la nueva funciona, el enlace de restablecimiento se gasta. El cambio de credencial, sin
embargo, no alcanza a lo que esa credencial ya había emitido. La sesión abierta sigue autorizando y
la concesión de refresco —el «recordarme» del móvil— canjea y devuelve sesiones nuevas. Quien tenía
la contraseña vieja no necesita adivinarla: entra por una puerta que el cambio no cerró.

## La hipótesis, en una línea falsable

**Si el cambio de credencial solo reescribe el registro de la contraseña, sin comparar la credencial
con la que nació cada pieza emitida, entonces toda sesión y toda concesión anteriores siguen siendo
honradas, y la concesión permite volver a entrar indefinidamente sin conocer la contraseña nueva.**

Se refuta con una pieza que nació con la credencial vieja y que, después del cambio, deja de ser
honrada **sin que nadie la haya recorrido para revocarla**. Eso es exactamente lo que hace
[patch_secure.py](patch_secure.py): no toca `restablecer`.

## Anatomía del fallo

El registro guarda, en cada pieza emitida, la huella de la credencial con la que nació:

```python
def entrar(usuario, clave):
    cuenta = _exigir_credencial(usuario, clave)
    sid = _nuevo("sid")
    SESIONES[sid] = {"usuario": usuario, "credencial": cuenta["clave"], "revocada": False}
    return sid
```

La anotación **existe**. El defecto no es que falte el dato: es que nadie lo pregunta. `restablecer`
asienta la credencial nueva y gasta el token correctamente, y las dos funciones que honran lo emitido
miran el almacén sin leer la anotación que ellas mismas escribieron:

```python
def _restablecer_canonico(token, clave_nueva):
    usuario, pendiente = _pendiente(token, clave_nueva)
    USUARIOS[usuario]["clave"] = _huella(clave_nueva)
    pendiente["gastado"] = True
    return {"usuario": usuario, "clave": "asentada"}          # la credencial vieja deja de entrar

def autorizar(sid, estricto=True):
    sesion = SESIONES.get(sid)
    if sesion is None:
        raise Rechazo("sesion desconocida")
    if sesion["revocada"]:
        raise Rechazo("sesion revocada")
    return {"usuario": sesion["usuario"]}                      # ...y su sesion sigue valiendo
```

Dos consecuencias, y la segunda es la que hace que el defecto sobreviva al arreglo obvio:

1. **La sesión abierta sobrevive.** El `sid` es un identificador opaco que el sistema emitió; el
   cambio de contraseña no lo mira.
2. **La concesión emite sesiones nuevas.** Revocar las sesiones no cierra nada: el refresco vuelve a
   emitirlas, y vuelve a pasar por `autorizar`, que tampoco pregunta. La puerta que se cerró no es la
   única que entra al mismo cuarto.

El informe dirá «la sesión abierta sobrevive al cambio de contraseña». Es verdad y es la mitad: la
frase nombra la pieza, no la causa. La causa es que **la credencial es un dato del registro y no una
condición de validez**. Mientras sea un dato, cada almacén nuevo repite el fallo y cada ruta nueva
—API, panel de administración, migración— reabre las dos puertas.

## Por qué el parche ingenuo no cierra

El ingenuo hace lo que el informe pide, literalmente:

```python
def _restablecer_ingenuo(token, clave_nueva):
    usuario, pendiente = _pendiente(token, clave_nueva)
    USUARIOS[usuario]["clave"] = _huella(clave_nueva)
    pendiente["gastado"] = True
    for sesion in SESIONES.values():
        if sesion["usuario"] == usuario:
            sesion["revocada"] = True            # recorre y revoca: cierra lo que el informe miraba
    return {"usuario": usuario, "clave": "asentada"}
```

La sesión anterior queda `[RECHAZADA]` y la concesión sigue `[CONCESION VIVA]`: el intruso canjea el
«recordarme», recibe un `sid` nuevo y entra. Medido: `--naive` da **RC 0** con una de las dos vías
abierta. El ingenuo cerró la vía que el informe nombraba y dejó intacta la clase.

Hay una segunda razón, más silenciosa: **enumera un almacén que tendrá que recordar**. El día que
alguien añada un tercer tipo de pieza —un `api-token`, un dispositivo de confianza, un enlace
mágico— el bucle del ingenuo no lo incluirá, y la omisión no produce ningún síntoma: las pruebas
seguirán verdes porque el almacén nuevo no existe todavía. Un enumerado que hay que mantener es una
promesa de que alguien se va a olvidar.

## El remedio

Una regla, y ninguna lista:

```python
def _nacida_con_la_vigente(anotada, usuario):
    cuenta = USUARIOS.get(usuario)
    return cuenta is not None and str(cuenta["clave"]) == anotada

def autorizar(sid, estricto=True):
    ...
    if estricto and not _nacida_con_la_vigente(sesion["credencial"], sesion["usuario"]):
        raise Rechazo("la credencial cambio despues de emitirse esta sesion")
```

`refrescar`, `sesion_vigente` y `concesion_vigente` hacen la misma pregunta. **`restablecer` queda
idéntica al sujeto vulnerable a propósito**: si el parche no toca la función que el informe señalaba
y el fallo desaparece, entonces el informe estaba señalando el síntoma y no la causa. Un almacén
nuevo que olvide anotar la credencial se ve, además, como un campo ausente en la comparación —un
error de desarrollo— y no como una limpieza que nadie escribió.

## Matriz medida

| sujeto | sesión abierta | concesión de refresco | control legítimo | RC |
|---|---|---|---|---|
| `app_vulnerable.py` | **SESIÓN VIVA** — autoriza después del cambio | **CONCESIÓN VIVA** — emite `sid` nuevo | ok | **0** |
| `patch_secure.py --naive` | RECHAZADA — recorrida y revocada | **CONCESIÓN VIVA** — igual | ok | **0** |
| `patch_secure.py` | RECHAZADA — nació con otra credencial | RECHAZADA — nació con otra credencial | ok | **1** |
| servicio que no autentica | NO EJERCIDA — no deja cambiar nada | NO EJERCIDA — igual | **NO** | **3** |

```bash
python3 exploit_poc.py                                  # RC 0 · las dos vías abren
python3 exploit_poc.py --app patch_secure.py --naive    # RC 0 · la concesión sigue abierta
python3 exploit_poc.py --app patch_secure.py            # RC 1 · ninguna de las dos se honra
```

El control corre dentro de la misma corrida. Un sujeto que rechaza **todo** deja las dos vías en
`NO EJERCIDA`, que leídas solas absolverían al sistema más seguro de todos: el apagado. Para A07 el
falso verde tiene esa forma exacta —«no hay sesiones vivas» se lee como «no hay sesiones que
revocar», y es compatible con un servicio que no autentica a nadie—. Los cinco controles legítimos lo
ponen en `3`: la credencial nueva entra, la vieja ya no entra, una sesión abierta **después** del
cambio autoriza, una concesión abierta **después** del cambio refresca, y un token gastado no se
reusa. Falla cualquiera de los cinco → `RC 3`, porque sin ellos el sujeto no demuestra que esté vivo.
Ese sujeto es [control_no_existe.py](control_no_existe.py) y `./verificar-capsulas.sh` lo corre en
cada push.

## El falsador del oráculo

Esta cápsula se mide **en las dos direcciones**: su falla es de estado —lo que hay que mirar no es el
retorno, es si la pieza sigue siendo honrada— y su PoC tiene que desconfiar de un rechazo declarado.
La primera lectura, obvia, sería mirar el registro crudo (`sesion["revocada"]`).
Es la lectura equivocada: el parche canónico **no marca nada como revocado**, así que esa lectura
daría `[A CIEGAS]` contra el parche bueno. El lector correcto es «el sistema preguntado por su estado,
sin excepción de por medio» —`sesion_vigente` / `concesion_vigente`—, que en el canónico devuelve
`False` y en el vulnerable `True`.

La prueba de que el PoC no se cree un rechazo está en el falsificador que ya trae el repo
([../parche_mentiroso.py](../parche_mentiroso.py)), sin mutante nuevo: envuelve cada función para
consultar a `patch_secure` como testigo, ejecuta el sujeto vulnerable y después lanza el rechazo.
Medido: `[FALSADOR] rechazos fingidos=2 ['autorizar', 'refrescar']`. Los dos rechazos se fabrican y el
PoC los ve: `[A CIEGAS]` ×2, `RC 0`. La mentira no le sirve.

La elección del lector se midió, y el lector equivocado no falla en la dirección que se espera:

| lector | contra el parche bueno | contra el mentiroso | veredicto |
|---|---|---|---|
| registro crudo (`revocada`) | **`[A CIEGAS]`** ×2 — `RC 0` | `[A CIEGAS]` ×2 — `RC 0` | **no distingue**: acusa al que cierra |
| estado del sistema (`*_vigente`) | `[RECHAZADA]` ×2 — `RC 1` | `[A CIEGAS]` ×2 — `RC 0` | separa los dos sujetos |

El registro crudo **acierta contra el mentiroso y miente contra el parche bueno**, porque el canónico
no revoca nada: invalida por comparación. Un PoC que hubiera confiado en la etiqueta sin correrla
contra el parche habría publicado un falso rojo —el error en la dirección segura, que no bloquea
ninguna entrega y por eso nadie corrige—. Lo que separa a los dos lectores no es el fervor: es haber
corrido el oráculo contra el sujeto que debe absolver.

## Frontera: qué NO demuestra

- **`RC 1` no dice que el sistema sea seguro.** Dice que ninguna pieza emitida con la credencial vieja
  se honra, en este sujeto. Un sistema real puede tener piezas en otro almacén, caché de sesión en
  un CDN, o un token de API con vida propia: ninguno se mide aquí.
- **No mide el cambio hecho por administración.** El sujeto solo cambia la credencial por el enlace
  de restablecimiento. Un `reset` desde un panel de soporte que reescriba la huella por otra ruta
  produce el mismo fallo y no se ejerce; la regla del canónico lo cubriría, la prueba no lo demuestra.
- **No mide concurrencia.** El evento precario —canjear el refresco *mientras* se cambia la
  contraseña— necesita dos hilos o dos procesos, y aquí todo es secuencial. Es la ventana real de
  producción y esta cápsula no la abre.
- **No mide el segundo factor ni el correo de aviso.** Un sistema que notifica «tu sesión se cerró»
  y no la cierra comete este mismo fallo con un agravante. Fuera de alcance.
- **`RECHAZADA` se lee como cierre y puede ser un falso cierre.** Un sujeto que rechazara *todo*
  pasaría las dos vías con esa etiqueta; los cinco controles legítimos son lo que lo impide. La
  distinción entre «rechazo declarado» (`ValueError`) y «rotura» (cualquier otra excepción) sostiene
  la etiqueta, y el rechazo **se mide**: si la pieza se sigue honrando, la vía vale `[A CIEGAS]`.
- **No mide el coste de fallar cerrado.** Invalidar todas las sesiones en cada cambio de credencial
  expulsa también al dueño legítimo de todos sus dispositivos. Aquí se elige seguridad y no se
  cuantifica lo que cuesta; una tienda con miles de sesiones podría elegir lo contrario, y esa
  decisión no se toma aquí.

## Origen

Caso propio, escrito desde cero, sin servidor ni dependencias externas. Nació de una corrección de
sujeto: la primera candidata era la reutilización del token de restablecimiento, que era la
[008](../008-insecure-design-coupon-ledger/) con otro sustantivo —un registro de un solo uso que no
cuenta sus usos ya está ahí—. Lo que A07 tiene de propio no es el token: es que **la credencial es el
sujeto y lo emitido con ella es el predicado**, y que el arreglo evidente —recorrer y revocar— deja la
segunda puerta abierta.

La referencia externa es la categoría pública **OWASP A07:2021 — Identification and Authentication
Failures**. MIT. Ver [../LICENSE](../LICENSE).
