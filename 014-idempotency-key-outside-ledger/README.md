# 014 · La clave de idempotencia vive en el mostrador y el libro no la conoce

invariante: estado
falsador: verifica

Un comercio cobra por tres puertas que escriben en el mismo libro: el mostrador, el aviso del
proveedor y la conciliación del día. La clave de idempotencia —el número que dice «este evento ya
se aplicó»— se apunta en un registro aparte que **sólo consulta el mostrador**. Las otras dos
puertas escriben directo en el libro. El mismo evento entra dos veces, el comercio cobra dos veces
y ningún asiento recuerda que su clave ya estaba.

## La hipótesis, en una línea falsable

> Cuando el libro de asientos no guarda la clave de idempotencia y el candado vive fuera de él,
> toda puerta que no consulte ese candado puede asentar el mismo evento otra vez, **y el libro
> sigue cuadrando**: no queda ninguna marca que diga que el asiento está repetido.

`exploit_poc.py` la falsa por código de salida, no por lo que imprime.

## Anatomía del fallo

```python
CLAVES: set[str] = set()          # el candado, fuera del libro

def cobrar(clave, monto):         # el mostrador: consulta el candado
    validado = validar(clave, monto)
    if clave in CLAVES:
        raise Rechazo(f"la clave {clave} ya se cobro por el mostrador")
    asiento = _asentar(clave, validado, "mostrador")
    CLAVES.add(clave)
    return asiento

def reenviar(clave, monto):       # el aviso del proveedor: escribe y no consulta nada
    return _asentar(clave, validar(clave, monto), "reenvio")
```

y del lado de la conciliación, la misma escritura sin candado:

```python
def conciliar(clave, monto):
    return _asentar(clave, validar(clave, monto), "conciliacion")
```

Las tres funciones son correctas por separado. `validar` no miente: el dato es válido. `_asentar`
tampoco: guarda lo que le dan. El defecto es de **geometría del invariante**: la idempotencia se
guardó en un objeto que el libro no contiene, así que el invariante vale para la puerta que se
acuerda de consultarlo y no vale para el dato. Un webhook reintentado por el proveedor —el caso
más común de la vida real, no un ataque— entra dos veces.

```
$ python3 app_vulnerable.py --clave P-9 --monto 10
asiento: {'clave': 'P-9', 'monto': 10.0, 'puerta': 'mostrador'}
el libro suma 10.0 · asientos: 1 · claves apuntadas por el mostrador: 1
```

Una sola puerta hace lo correcto. El PoC entra por las otras dos:

```
$ python3 exploit_poc.py
SUJETO: app_vulnerable.py
  [DUPLICA] el aviso del proveedor reasienta un cobro ya hecho: el mismo evento dejo 2 asientos para la clave P-1001
  [DUPLICA] la conciliacion del dia reasienta lo que ya venia en el libro: el mismo evento dejo 2 asientos para la clave P-2002
  [MEDICION] el libro suma 40.0 en 4 asientos, apunta 2 claves y guarda 2 asientos para P-1001
  [CONTROL] un cobro por el mostrador queda asentado exactamente una vez -> si (1 asiento)
  [CONTROL] el mostrador rechaza el reintento de la misma clave        -> si
EXPLOTADO: el mismo evento entro mas de una vez porque la clave vive fuera del libro
```

Dos claves, cuatro asientos, `40.0` cobrados: **el doble de lo que cada clave autoriza**. Y el
libro no está corrupto — está cuadrado consigo mismo. Un arqueo por importe no lo ve; sólo lo ve
un arqueo por clave, que es exactamente el índice que el libro no tiene.

## Por qué el parche ingenuo no cierra

El informe dice «el aviso del proveedor duplica el cobro». El ingenuo arregla **eso**: añade la
comprobación a la puerta que el informe nombró.

```python
def reenviar(clave, monto):
    if _ya_asentada(clave):        # el caso reportado, cerrado
        raise Rechazo(...)
```

```
$ python3 exploit_poc.py --app patch_secure.py --naive
  [UNICA] el aviso del proveedor reasienta un cobro ya hecho: la puerta rechazo el segundo asiento: la clave P-1001 ya tiene asiento en el libro
  [DUPLICA] la conciliacion del dia reasienta lo que ya venia en el libro: el mismo evento dejo 2 asientos para la clave P-2002
  [MEDICION] el libro suma 30.0 en 3 asientos, ...
```

La puerta 1 cerró y la 2 sigue abierta. El importador nocturno no es un atacante: es un fichero
que se reimporta. Se cerró el síntoma con nombre —una puerta— y quedó la clase: **mientras el
candado no esté en el libro, cada puerta nueva nace sin él.**

## El remedio

```python
def _ya_asentada(clave: str) -> bool:
    return any(asiento["clave"] == clave for asiento in LIBRO)

def _asentar(clave, monto, puerta):
    ...
```

La comprobación se muda al **único punto por el que pasan las tres puertas**. El parche canónico
no enumera puertas: hace que el asiento sea su propio candado, y una cuarta puerta —un reembolso,
un reintento, un importador nuevo— nace cerrada porque no hay otra forma de escribir en el libro.
Es la diferencia entre arreglar una puerta y arreglar el almacén: la primera se reabre con el
siguiente *endpoint*, la segunda no.

## Matriz medida

| sujeto | el aviso del proveedor | la conciliación del día | control legítimo | RC |
|---|---|---|---|---|
| `app_vulnerable.py` | **DUPLICA** — 2 asientos | **DUPLICA** — 2 asientos | ok | **0** |
| `patch_secure.py --naive` | UNICA — rechaza | **DUPLICA** — 2 asientos | ok | **0** |
| `patch_secure.py` | UNICA — rechaza | UNICA — rechaza | ok | **1** |
| libro que no asienta | NO EJERCIDA — sin asiento | NO EJERCIDA — sin asiento | **NO** | **3** |

```bash
python3 exploit_poc.py                                  # RC 0 · el evento entra dos veces
python3 exploit_poc.py --app patch_secure.py --naive    # RC 0 · la clase sigue abierta
python3 exploit_poc.py --app patch_secure.py            # RC 1 · el libro es el candado
```

El control corre dentro de la misma corrida. Un sujeto que acepta el cobro y **no lo guarda** deja
las dos vías en `NO EJERCIDA`: un lector que sólo mirase esas etiquetas lo daría por bueno, porque
«no hay segundo asiento» y «no hay ni el primero» se leen igual. El control legítimo —un cobro por
el mostrador tiene que quedar asentado exactamente una vez— lo pone en `3`. Ese sujeto es
[control_libro_que_olvida.py](control_libro_que_olvida.py) y `./verificar-capsulas.sh` lo corre en
cada push.

El mismo control sostiene el falsificador: contra
[../parche_mentiroso.py](../parche_mentiroso.py) —un sujeto que hace el daño y **después** lanza el
rechazo declarado— el PoC devuelve RC 0. Si se creyera la excepción publicaría `UNICA` y RC 1: un
parche que finge cerrar pasaría por parche. La diferencia entre «rechazo declarado» (`ValueError`)
y «rotura» (cualquier otra excepción) es la que sostiene esa lectura.

## Frontera: qué NO demuestra

- **`RC 1` no dice que el servicio sea seguro.** Dice que ninguna de las dos vías dejó un segundo
  asiento **para la misma clave**. Una clave que el llamante elija distinta en cada reintento sigue
  duplicando, y esa frontera es de quien llama, no del libro.
- **No mide concurrencia.** Las dos vías son secuenciales y el libro es una lista en memoria. Un
  `SELECT` seguido de un `INSERT` en dos hilos produce la misma duplicación con el candado en su
  sitio, y **eso no se mide aquí**: esta casa no tiene lector de carreras, y la cápsula lo dice en
  vez de insinuar que lo cubre.
- **No mide la ventana de retención de la clave.** Cuánto tiempo hay que recordar un evento para
  que un reintento tardío no duplique es una decisión de negocio; el PoC usa claves que nunca
  caducan.
- **La clave es del llamante.** Un servicio que acepta cualquier clave acepta también la que
  collide con la de otro cliente. El aislamiento por cliente no se mide aquí.
- **No mide el coste.** `any(...)` recorre el libro en cada asiento. Cuánto cuesta eso en una tabla
  real —y qué índice lo arregla— no se mide en esta cápsula.

## Origen

Caso propio, escrito desde cero, sin servidor ni dependencias externas. La clase no es de este
laboratorio: la forma canónica del defecto es la clave de idempotencia guardada **fuera** de la
entidad que la clave protege, y el síntoma que la delata es siempre el mismo —el libro cuadra por
importe y no por clave—.

La referencia pública es la categoría **OWASP A04:2021 — Insecure Design**: el fallo no está en
una comprobación mal escrita sino en un invariante que no se diseñó para sobrevivir a la segunda
puerta. El patrón de CWE es **CWE-837 (Improper Enforcement of a Single, Unique Action)**.

MIT. Ver [../LICENSE](../LICENSE).
