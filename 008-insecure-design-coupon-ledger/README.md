# 008 · Cupón de un solo uso que nunca cuenta sus usos

Un comercio declara su cupón de bienvenida **de un solo uso por cuenta**. El catálogo lo
dice; el servicio resuelve el cupón, aplica el porcentaje y devuelve el importe a cobrar.
Nadie cuenta los usos, y cualquier importe es un importe.

## La hipótesis, en una línea falsable

> Hay dos compras que el diseño declara imposibles —la segunda con el mismo texto, y una
> con importe negativo— que el servicio atiende y devuelve con descuento.

`exploit_poc.py` la falsa por código de salida, no por lo que imprime.

## Anatomía del fallo

```python
CUPONES = {"BIENVENIDA": {"porcentaje": 50, "usos_por_cuenta": 1}}
...
descuento = compra_centavos * cupon["porcentaje"] // 100   # y aqui termina el diseno
```

El fallo no es una comparación mal escrita: es una **regla que sólo existe como texto**.
`usos_por_cuenta` se declara en el catálogo y no lo lee nadie, así que el cupón se comporta
como ilimitado. Y `compra_centavos` entra sin comprobar el signo, de modo que un importe
negativo produce un descuento negativo y un total a cobrar a favor del comprador.

Es un fallo de **diseño**, no de implementación: la clase entera —límite de uso, importe
válido, idempotencia— no se decidió, y por eso no hay línea que corregir.

El sujeto no levanta servidor. Es **una función pura del canje**, así que lo que se mide es
el criterio y no el transporte — y la corrida es determinista sin red ni reloj.

## Por qué el parche ingenuo no cierra

El informe dice «la misma cuenta reutiliza su cupón de bienvenida». El arreglo que se
reporta añade un registro de usos… y lo escribe **con el código tal como llegó del cliente**,
mientras la búsqueda del cupón sí normaliza:

```python
usos = _USOS_INGENUO.get((usuario, codigo), 0)   # codigo crudo
```

Buscar normalizando y contar sin normalizar deja **dos nombres para el mismo cupón**:

```
$ python3 exploit_poc.py --app patch_secure.py --naive
[BLOQUEADA] reutilizacion con el mismo texto: rechazado (CuponAgotado)
[REUTILIZADA] reutilizacion con otro texto: segundo descuento de 50000 con otro texto
```

`"BIENVENIDA"` cuenta como usado; `"  Bienvenida  "` no. El registro existe, se consulta,
se escribe — y no registra nada. La compra negativa sigue abierta por la misma razón: el
informe hablaba de reutilización, y se arregló exactamente lo que decía el informe.

## El remedio

```python
if compra_centavos <= 0:
    raise CompraInvalida(...)
usos = _USOS_CANONICO.get((usuario, clave), 0)   # clave ya normalizada
if usos >= cupon["usos_por_cuenta"]:
    raise CuponAgotado(...)
_USOS_CANONICO[(usuario, clave)] = usos + 1      # se anota antes de conceder
```

Una sola normalización en todo el servicio: la misma cadena que se usa para **buscar** es la
que se usa para **contar**. El uso es parte del sujeto, no del catálogo. El importe se valida
antes de calcular, y el uso se anota antes de conceder — un fallo al cobrar no devuelve el
cupón.

## Matriz medida

| sujeto | mismo texto | otro texto | importe negativo | cupón legítimo | RC |
|---|---|---|---|---|---|
| `app_vulnerable.py` | REUTILIZADA | REUTILIZADA | REUTILIZADA | concedido | **0** |
| `patch_secure.py --naive` | BLOQUEADA | **REUTILIZADA** | **REUTILIZADA** | concedido | **0** |
| `patch_secure.py` | BLOQUEADA | BLOQUEADA | BLOQUEADA | concedido | **1** |

```bash
python3 exploit_poc.py                                  # 0  el sujeto cae
python3 exploit_poc.py --app patch_secure.py --naive    # 0  el ingenuo también
python3 exploit_poc.py --app patch_secure.py            # 1  el canónico aguanta
```

El control corre dentro de la misma corrida, con dos cuentas nuevas: si el sujeto niega
también el cupón legítimo, sale RC `3` — rompió, no cerró. Comprobado con un sujeto que
niega todo: cierra las tres vías y aun así **no** se lleva el `1`.

## Un rechazo tiene que estar declarado

La primera versión de este PoC atrapaba `Exception`. Con eso, un sujeto que **revienta** en la
rama del código con relleno —`ValueError: rama de normalizacion sin implementar`— salía como
`[BLOQUEADA]`, o sea `RC 1`: un error interno contado como cupón cerrado.

Ahora el PoC toma las excepciones del **propio módulo del sujeto** y sólo absorbe esas:

```python
RECHAZOS_DECLARADOS = ("CuponInvalido", "CuponAgotado", "CompraInvalida")
except rechazos as exc:      # rechazos = lo que el sujeto declara, no lo que el PoC supone
```

Cualquier otra excepción sube y la corrida termina en `RC 3`. Medido con un sujeto que declara
los tres rechazos pero lanza `ValueError` sólo con el código con relleno: **antes `RC 1`,
después `RC 3`**. Ese sujeto es [control_falso_cierre.py](control_falso_cierre.py) y
`./verificar-capsulas.sh` lo corre en cada push: si volviera a dar `RC 1`, el comando se
pone rojo. Si el sujeto no declara ninguno, el PoC avisa por `stderr`
(`AUSENCIA: …`) en vez de callarse: la cápsula mide fronteras declaradas, no fronteras
adivinadas.

## Frontera: qué NO demuestra

- **No mide concurrencia.** Los canjes se atienden uno tras otro. Dos peticiones simultáneas
  sobre la misma cuenta pueden leer el mismo contador antes de que nadie escriba: eso es
  `check-then-act` sobre estado compartido y es otro sujeto.
- **No mide idempotencia de red.** Un reintento por timeout del mismo canje es un tercer
  caso —hace falta una clave de idempotencia— que esta cápsula no ejerce.
- **No es un escáner.** Hay tres vectores. Un cuarto fuera de esta lista puede seguir abierto
  y el RC `1` no lo desmiente.

## Origen

Caso propio, escrito desde cero, sin servidor ni dependencias. La referencia externa es la
categoría pública **OWASP A04:2021 — Insecure Design**.

MIT. Ver [../LICENSE](../LICENSE).
