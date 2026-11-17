# 011 · El registro pierde justo el evento que importa, y la vigilancia lo da por registrado

invariante: estado
falsador: verifica

Una caja mueve dinero y tiene que dejar rastro de cada movimiento. El sumidero del registro falla,
el fallo se absorbe **después** de asentar el efecto, y el panel del propio sistema cuenta las
llamadas al registro en vez de los asientos que el sumidero conserva. El cliente no manipula nada:
basta con que el registro tenga un mal día.

## La hipótesis, en una línea falsable

> Cuando el rastro se escribe **después** del efecto y su fallo se absorbe, toda operación que
> coincida con una caída del sumidero queda sin prueba; y un panel que cuenta en el sitio de
> llamada publica brecha cero sobre un registro vacío.

`exploit_poc.py` la falsa por código de salida, no por lo que imprime.

## Anatomía del fallo

```python
MOVIMIENTOS[orden_id] = {"orden": orden_id, "monto": monto}   # el efecto: mueve dinero
LLAMADAS_AL_REGISTRO += 1                                     # se cuenta la llamada
try:
    _escribir_evento({"orden": orden_id, "monto": monto})      # el rastro, después
except SumideroNoDisponible:
    pass    # «el registro no debe tumbar una operación que el cliente ya pagó»
```

y del lado del panel:

```python
operaciones = len(MOVIMIENTOS)
eventos = LLAMADAS_AL_REGISTRO          # llamadas, no asientos del sumidero
return {"operaciones": operaciones, "eventos": eventos, "brecha": operaciones - eventos}
```

Las dos piezas son defendibles por separado y el fallo nace del orden entre ellas. Absorber el
fallo de un registro es una decisión de disponibilidad legítima —un log no debería tumbar la caja—
y contar en el sitio de llamada es la forma natural de escribir un contador. El defecto es que
**el efecto se asienta antes de que su prueba exista**, y que la vigilancia mide la intención
en vez de medir el registro.

Con el sumidero caído, el sujeto responde sin un solo error:

```
$ python3 app_vulnerable.py --orden A-2 --monto 10 --sumidero-caido
{"orden": "A-2", "monto": 10.0}
RASTRO: no
{"operaciones": 1, "eventos": 1, "brecha": 0, "durables": 0}
```

Un movimiento de 10 se asentó, no hay evento que lo pruebe, y el panel publica `brecha 0`. Compárese
con la misma caja con el sumidero arriba:

```
$ python3 app_vulnerable.py --orden A-1 --monto 10
{"orden": "A-1", "monto": 10.0}
RASTRO: si
{"operaciones": 1, "eventos": 1, "brecha": 0, "durables": 1}
```

Las dos líneas del panel son idénticas en todo lo que un operador mira. La diferencia está en un
campo que el panel no habría mostrado si la cápsula no lo pidiera: `durables`.

```
$ python3 exploit_poc.py
SUJETO: app_vulnerable.py
  [A CIEGAS] el efecto se asienta sin rastro durable: la transferencia de 10.0 se asento con el sumidero caido y el sumidero conserva 0 eventos: el efecto existe y su prueba no
  [DECLARA CUADRE] la vigilancia publica cuadre con el sumidero vacio: el panel publica 2 operaciones y 2 eventos (brecha 0) con el sumidero en 0: el sistema no solo perdio el rastro, lo dio por registrado
  [MEDICION] el libro movio 2 y el sumidero conserva 0: 2 operaciones sin prueba
  [CONTROL] una transferencia normal se ejecuta y deja rastro -> si
  [CONTROL] un monto no positivo no entra                     -> si
EXPLOTADO: una operacion se asento con el sumidero caido y no dejo evento durable
EXPLOTADO: la vigilancia publico brecha cero con el sumidero vacio
```

Dos movimientos, cero pruebas, y un panel contento. No es un dato corrupto que alguien vaya a
notar: es un cuadre que cuadra.

## Por qué el parche ingenuo no cierra

El informe dice «el panel publicó brecha cero con el sumidero caído». El ingenuo arregla **eso**:
la cuenta se toma del sumidero.

```python
eventos = len(SUMIDERO)     # el caso reportado, cerrado
```

La brecha se vuelve visible y el informe se cierra. Lo que no se toca es el orden:

```
$ python3 exploit_poc.py --app patch_secure.py --naive
  [A CIEGAS] el efecto se asienta sin rastro durable: la transferencia de 10.0 se asento con el sumidero caido ...
  [ALERTA] la vigilancia publica cuadre con el sumidero vacio: el panel ve una brecha de 2: la perdida se detecta (y el movimiento sin rastro sigue existiendo)
  [MEDICION] el libro movio 2 y el sumidero conserva 0: 2 operaciones sin prueba
```

La vía 2 cerró y la vía 1 sigue abierta. El sistema ahora **avisa** de una operación que ya
ocurrió y que nadie puede reconstruir. Se mejoró la detección y se dejó intacta la pérdida: para
una auditoría que se vende como *fail-closed*, avisar de que el rastro no existe no es tenerlo.

## El remedio

```python
try:
    _escribir_evento(evento)                     # primero el rastro
except SumideroNoDisponible as exc:
    raise Rechazo(f"sin rastro durable no hay operación: {exc}") from exc
if not SUMIDERO or SUMIDERO[-1] != evento:
    raise Rechazo("el sumidero no devuelve el evento que se le entregó")   # se relee
MOVIMIENTOS[orden_id] = {"orden": orden_id, "monto": monto}                # después el efecto
```

**El rastro va antes que el efecto, y se relee.** La primera regla es una decisión de negocio —la
caja prefiere no mover dinero a moverlo sin poder contarlo— y la segunda es la que sobrevive al
tiempo: no necesita saber *por qué* falló el sumidero, comprueba la propiedad. Y el panel cuenta
en el sumidero, así que una brecha se ve en vez de publicarse como cuadre.

## Matriz medida

| sujeto | efecto sin rastro | panel con el sumidero vacío | control legítimo | RC |
|---|---|---|---|---|
| `app_vulnerable.py` | **A CIEGAS** — 2 movidos, 0 durables | **DECLARA CUADRE** — brecha 0 | ok | **0** |
| `patch_secure.py --naive` | **A CIEGAS** — igual | ALERTA — ya ve la brecha | ok | **0** |
| `patch_secure.py` | RECHAZADA — sin rastro no hay operación | RECHAZADA — la operación no entra | ok | **1** |
| servicio que no opera | RECHAZADA — «no autorizada» | RECHAZADA — nada que tapar | **NO** | **3** |

```bash
python3 exploit_poc.py                                  # 0  mueve sin rastro
python3 exploit_poc.py --app patch_secure.py --naive    # 0  la clase sigue abierta
python3 exploit_poc.py --app patch_secure.py            # 1  la frontera rechaza
```

El control corre dentro de la misma corrida. Un sujeto que rechaza **todo** deja las dos vías en
`RECHAZADA`, que leídas solas absolverían al sistema más seguro de todos: el que está apagado. El
control legítimo —una transferencia normal tiene que ejecutarse **y** dejar rastro— lo pone en
`3`. Ese sujeto es [control_no_opera.py](control_no_opera.py) y `./verificar-capsulas.sh` lo corre
en cada push.

Para A09 el falso verde tiene precisamente esa forma: «no hay eventos» se lee como «no hay
incidentes», y los dos enunciados son incompatibles con un sistema que funciona.

## El falsador del oráculo

Un PoC que certifica tiene que fallar cuando el sujeto miente. Este asienta el efecto y **después**
declara el rechazo `ValueError` —el gesto más plausible de un parche apresurado, «revierto lo que no
puedo registrar» sin revertir nada—. Es una línea sobre `patch_secure.py`, y la cápsula sigue
teniendo cinco archivos porque el mutante es un diff, no un sujeto:

```diff
 def _ejecutar_canonico(orden_id: str, monto: float) -> dict[str, Any]:
     _validar(monto)
     evento = _evento(orden_id, monto)
+    MOVIMIENTOS[orden_id] = {"orden": orden_id, "monto": monto}
     try:
         _escribir_evento(evento)
     except SumideroNoDisponible as exc:
         raise Rechazo(f"sin rastro durable no hay operación: {exc}") from exc
```

| oráculo | contra el mutante | RC |
|---|---|---|
| primera versión | `BLOQUEADO`, y su propia línea `[MEDICION]` decía *2 operaciones sin prueba* | **1** |
| esta versión | `A CIEGAS` — «un rechazo que no deshace el efecto no es un cierre» | **0** |

La contradicción estaba impresa en la salida y nadie la leía: el `[MEDICION]` contaba los movimientos
sin prueba y las vías ya habían devuelto `RECHAZADA` sin mirar. Se corrigió midiendo el rechazo,
no creyéndolo. La matriz de arriba no cambió: los tres sujetos reales dan los mismos RC antes y
después (medido, `0 / 0 / 1 / 3 / 3`).

## Frontera: qué NO demuestra

- **`RC 1` no dice que el sistema sea auditable.** Dice que ninguna de las dos vías dejó un efecto
  sin rastro con este sumidero. Un sumidero que **acepta** y luego pierde el evento —rotación,
  retención de siete días, un `buffer` sin `flush`— produce la misma clase de fallo y aquí no se
  mide: este sumidero o acepta o lanza.
- **No mide durabilidad real.** El sumidero es una lista en memoria. `fsync`, replicación y
  retención quedan fuera, y son donde el fallo vive en producción.
- **No mide la ventana entre efecto y rastro.** Aquí el rastro va inmediatamente antes; en un
  sistema con cola, la ventana entre encolar y asentar es la superficie, y esta cápsula no la abre.
- **No mide integridad ni orden.** Un registro completo pero manipulable, o completo y en desorden,
  se distinguiría con una cadena de hashes o una firma: fuera de alcance.
- **`RECHAZADA` se lee como cierre y puede ser un falso cierre.** Un sujeto que rechazara *todo*
  pasaría las dos vías con esa etiqueta; el control legítimo es lo que lo impide. La distinción
  entre «rechazo declarado» (`ValueError`) y «rotura» (cualquier otra excepción) sostiene la
  etiqueta, y el rechazo **se mide**: si el efecto quedó asentado igual, la vía vale `[A CIEGAS]`.
  Esa comprobación no estaba en la primera versión de este PoC y la añadió un revisor que señaló el
  hueco; el falsador está abajo, con un mutante que asienta el efecto y después declara el rechazo.
- **No mide el coste de fallar cerrado.** Rechazar operaciones con el registro caído es un
  intercambio entre disponibilidad y trazabilidad. La cápsula elige trazabilidad y no cuantifica lo
  que cuesta; una caja de pagos podría elegir lo contrario, y esa decisión no se toma aquí.

## Origen

Caso propio, escrito desde cero, sin servidor ni dependencias externas. La mecánica que modela está
medida en la biblioteca estándar, no recordada. Con `/usr/bin/python3` 3.9.6, el 16-Nov-2026:

```python
class FlujoRoto:                     # el sumidero que no admite escrituras
    def write(self, texto): raise OSError("el sumidero no admite escrituras")

log = logging.getLogger("auditoria")
log.addHandler(logging.StreamHandler(FlujoRoto()))
log.setLevel(logging.INFO)           # sin esto el registro no llega ni al sumidero
log.info("transferencia 10.0")       # no lanza: imprime "--- Logging error ---" y sigue
```

`logging.raiseExceptions = False` y la misma llamada no lanza **ni imprime**. La absorción no vive
en `Handler.handle` —un `emit` que lanza sí propaga, medido— sino en `StreamHandler.emit`
(`logging/__init__.py:1086`), que desvía el fallo a `handleError` y devuelve el control al
llamador. Es decir: **fallar abierto es la política de fábrica del registro**, y cualquier capa que
lo envuelva hereda la forma.

El `setLevel` no es adorno: es la primera medición del propio fragmento. Sin él el logger hereda el
nivel `WARNING` de la raíz y `log.info` se descarta **antes** de tocar el sumidero —sin traza, sin
`--- Logging error ---`, sin nada—, que es la variante más barata de la misma pérdida: el evento no
llega, y la llamada tampoco avisa. El fragmento de arriba es el que se midió, no uno parecido.

La diferencia con esta cápsula es de grado, y se dice: la biblioteca al menos grita a `stderr`; el
sujeto no grita nada y además cuenta la llamada como si el asiento existiera. Lo que se publica es
la **clase** —registro después del efecto, y vigilancia que mide la intención— no el caso de una
biblioteca. La referencia externa es la categoría pública **OWASP A09:2021 — Security Logging and
Monitoring Failures**.

MIT. Ver [../LICENSE](../LICENSE).
