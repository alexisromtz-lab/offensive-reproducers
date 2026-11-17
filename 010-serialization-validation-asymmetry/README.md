# 010 · La validación acepta lo que su propia serialización no devuelve

invariante: estado
falsador: verifica

Un servicio valida el monto de un cobro y lo guarda como instantánea JSON. El monto pasa la
validación, la escritura lo guarda como otra cosa, y la decisión de negocio se toma leyendo lo
guardado. El cliente no rompe ninguna regla: manda un número.

## La hipótesis, en una línea falsable

> Cuando la frontera de escritura es una serialización, todo valor que el validador admita y la
> codificación no sepa representar se guarda **distinto de como se validó**, y una regla que lea
> lo guardado decide sobre un dato que nadie validó.

`exploit_poc.py` la falsa por código de salida, no por lo que imprime.

## Anatomía del fallo

```python
validado = validar(monto)                       # inf < 0 es False: pasa
instantanea = {"monto": _a_json(validado)}      # inf no está en JSON: se escribe None
LIBRO[orden_id] = json.loads(json.dumps(instantanea))
```

y del lado de la lectura:

```python
if guardado is None:
    return True    # «sin monto declarado no hay techo que aplicar»
```

Las dos piezas son correctas por separado y el fallo nace del orden entre ellas. `validar` no
miente: `inf` es un número y no es negativo. La codificación tampoco: JSON no tiene `Infinity`, y
`null` es la representación honesta de «no hay número aquí». El defecto es que **nadie comprobó que
lo que se guarda vuelve igual a lo que se validó**, y que la lectura interpretó el hueco como
permiso.

El monto entra por la red. `{"monto": 1e400}` es JSON válido y `json.loads` lo devuelve como
`inf`: el ataque es un cuerpo de petición, no una llamada a una biblioteca.

```
$ python3 app_vulnerable.py --orden A-2 --monto '{"monto": 1e400}' --json --techo 10
{"orden": "A-2", "monto": null, "techo": 10.0}
COBRA: si
```

Un cobro sin monto fue admitido por encima de un techo de 10. Y el libro pierde el rastro:

```
$ python3 exploit_poc.py
SUJETO: app_vulnerable.py
  [CAMBIA] la escritura cambia el valor validado: se valido inf y la instantanea guarda None: la frontera admite lo que no puede devolver
  [ABIERTA] el techo se elude con un monto que no se puede guardar: un pago de {"monto": 1e400} fue admitido con techo 10.0: el asiento guarda monto=None y la lectura no aplico techo
  [MEDICION] el libro suma 0.0 y guarda 2 asientos: el asiento sin monto aporta cero
  [CONTROL] un monto normal bajo el techo entra -> si
  [CONTROL] un monto sobre el techo no entra    -> si
EXPLOTADO: el valor que la frontera admite no es el valor que la frontera devuelve
```

Dos asientos, y la suma es `0.0`: el cobro que el cliente declaró **no está en los libros** ni en
la cuenta que lo debería frenar. No es un dato corrupto que alguien vaya a notar — es un cero que
cuadra.

## Por qué el parche ingenuo no cierra

El informe dice «un cobro con `monto: 1e400` eludió el techo». El ingenuo arregla **eso**: la
lectura deja de fallar abierta.

```python
if guardado is None:
    return False    # el caso reportado, cerrado
```

El techo vuelve a aplicarse y el informe se cierra. Lo que no se toca es la escritura:

```
$ python3 exploit_poc.py --app patch_secure.py --naive
  [CAMBIA] la escritura cambia el valor validado: se valido inf y la instantanea guarda None: ...
  [BLOQUEADA] el techo se elude con un monto que no se puede guardar: el mismo pago no fue admitido con techo 10.0
  [MEDICION] el libro suma 0.0 y guarda 2 asientos: el asiento sin monto aporta cero
```

La vía 2 cerró y la vía 1 sigue abierta: el asiento «cobro de `null`» sigue naciendo de un monto
que el servicio aceptó. Cualquier otra regla que lea ese asiento —un reembolso, una conciliación,
un total— sigue leyendo un valor que nadie validó. Se cerró el síntoma con nombre y quedó la clase.

## El remedio

```python
guardado = json.loads(json.dumps(instantanea))
if guardado["monto"] != validado:
    raise Rechazo(f"la instantanea no devuelve lo validado: {validado!r} -> {guardado['monto']!r}")
```

**Se guarda y se relee antes de dar el asiento por bueno.** Esta regla no necesita saber que el
valor problemático es `inf`: comprueba la propiedad —lo guardado vuelve igual— y por eso sobrevive
a la siguiente codificación que alguien añada. El rechazo en la frontera (`math.isfinite`) es la
segunda capa, y la lectura falla cerrada.

## Matriz medida

| sujeto | escritura devuelve lo validado | techo sobre el pago del cliente | control legítimo | RC |
|---|---|---|---|---|
| `app_vulnerable.py` | **CAMBIA** — `inf` se guarda `None` | **ABIERTA** — admitido con techo 10.0 | ok | **0** |
| `patch_secure.py --naive` | **CAMBIA** — igual | BLOQUEADA — ya no se admite | ok | **0** |
| `patch_secure.py` | RECHAZADA — `inf` no entra | RECHAZADA — el pago no entra | ok | **1** |
| libro que no asienta | NO EJERCIDA — sin asiento | BLOQUEADA | **NO** | **3** |

```bash
python3 exploit_poc.py                                  # 0  cambia y se admite
python3 exploit_poc.py --app patch_secure.py --naive    # 0  la clase sigue abierta
python3 exploit_poc.py --app patch_secure.py            # 1  la frontera rechaza
```

El control corre dentro de la misma corrida. Un sujeto que acepta el cobro y **no lo guarda** deja
la vía 1 en `NO EJERCIDA` y la vía 2 en `BLOQUEADA`: un lector que sólo mirase esas dos etiquetas
lo daría por bueno. El control legítimo —un monto normal bajo el techo tiene que entrar— lo pone
en `3`. Ese sujeto es [control_sin_asiento.py](control_sin_asiento.py) y `./verificar-capsulas.sh`
lo corre en cada push.

## Frontera: qué NO demuestra

- **`RC 1` no dice que el servicio sea seguro.** Dice que ninguna de las dos vías cambió el valor
  guardado ni eludió el techo. Una tercera vía fuera de esta lista puede seguir abierta.
- **`RECHAZADA` se lee como cierre y puede ser un falso cierre.** Un sujeto que rechazara *todo*
  pasaría las dos vías con esa etiqueta; el control legítimo es lo que lo impide, y por eso no es
  decorativo. La distinción entre «rechazo declarado» (`ValueError`) y «rotura» (cualquier otra
  excepción) es la que sostiene la etiqueta.
- **No mide `-0.0`, subnormales ni precisión de coma flotante.** Un `float` que sobrevive al viaje
  no es un `float` que el consumidor interpreta igual: eso queda fuera, y se dice.
- **No mide el coste.** Comparar dos valores por asiento es gratis en este laboratorio; cuánto
  cuesta en una tabla real no se mide aquí.
- **El `1e400` es la puerta, no el mecanismo.** Cualquier codificación que no represente el dominio
  del validador —una columna `NUMERIC(10,2)`, un `int32`, una fecha sin zona— produce la misma
  asimetría. La cápsula mide una; la clase es la de todas.

## Origen

Caso propio, escrito desde cero, sin servidor ni dependencias externas. La clase está medida en una
biblioteca real con la que se escribe la mayoría de las APIs de Python —**pydantic 2.14.1**—, y la
medición es esta, no un recuerdo:

```python
class M(BaseModel):
    monto: float

M(monto=float("inf"))            # valida: monto=inf
M(monto=float("inf")).model_dump_json()   # '{"monto":null}'
M.model_validate_json('{"monto":null}')   # ValidationError: float_type
```

La biblioteca ofrece un interruptor para conservar el valor —`ser_json_inf_nan='constants'`— y
medido emite `{"monto":Infinity}`, que vuelve a validar: la asimetría se cierra por el lado de
**emitir JSON que no es RFC 8259**. Y el caso simétrico, donde la codificación no puede ni
intentarlo: un `bytes` no UTF-8 valida y su propio `model_dump_json()` lanza
`PydanticSerializationError`. Unos fallan en silencio y otro falla a gritos; esta cápsula ataca el
que falla en silencio.

Son defaults documentados, no un fallo reportado: por eso lo que se publica es la **clase** —toda
frontera que serializa sin releer— y no el caso de una biblioteca. La referencia externa es la
categoría pública **OWASP A08:2021 — Software and Data Integrity Failures**.

MIT. Ver [../LICENSE](../LICENSE).
