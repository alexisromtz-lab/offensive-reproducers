# 009 · Digest truncado a cuatro hex, con sal y todo

Un servicio guarda credenciales. El informe dice «las claves se guardan sin sal, así que una
tabla precompartida las abre todas». El arreglo añade sal por cuenta, la sal funciona, el
informe se cierra — y el servicio sigue cayendo igual.

## La hipótesis, en una línea falsable

> Con el digest recortado a cuatro hex hay 65 536 valores posibles, así que el volcado de la
> tabla basta para entrar en una cuenta **sin conocer su clave**, por dos vías distintas, y
> añadir sal no cierra ninguna de las dos.

`exploit_poc.py` la falsa por código de salida, no por lo que imprime.

## Anatomía del fallo

```python
ALMACEN[usuario] = hashlib.md5(clave.encode()).hexdigest()[:4]
```

Cuatro hex son **16 bits**. El espacio de digests posibles tiene 65 536 valores, y un espacio
de 65 536 valores no es un secreto: es una tabla de búsqueda. `respaldo()` publica el volcado
tal como lo leería quien lo obtiene, y con el volcado a la vista el ataque deja de ser
criptografía y pasa a ser aritmética.

La clave de las cuentas cae en dos vías, y son independientes:

1. **Una tabla cubre el espacio.** Enumerar claves y guardar `digest -> clave` produce, en
   **57 225** entradas, una tabla que contiene los digests de **las dos cuentas**. Se construye
   una vez y se usa contra todas.
2. **Segundo preimagen por cuenta.** Sin tabla previa: se enumera hasta dar con otra clave que
   produzca el mismo digest. Medido: **66 896** intentos para `ana`.

Ninguna de las dos claves está en un diccionario. No hace falta: lo que se enumera es el
espacio del **digest**, que cabe.

## Por qué el parche ingenuo no cierra

El ingenuo hace exactamente lo que el informe pedía —sal por cuenta— y conserva la truncación:

```python
sal = _md5("sal:" + usuario)[:8]
digest = _md5(sal + clave)[:4]     # la sal entró; los 16 bits siguen ahí
```

La sal hace su trabajo, y la cápsula lo publica cerrado en vez de disimularlo: **la vía 1 deja
de abrir**. Los dos digests del volcado siguen apareciendo en la tabla de 63 009 entradas —el
espacio es el mismo— pero el sujeto ya no los admite, porque su entrada cambió de forma.

```
$ python3 exploit_poc.py --app patch_secure.py --naive
[BLOQUEADA] una tabla que cubre el espacio: los 2 digests estan en la tabla de 63009 y el sujeto no los admite
[ABIERTA]   segundo preimagen por cuenta: ana abierta en 6243 intentos
```

Lo que la sal **no** puede hacer es devolver la entropía que la truncación se llevó. La sal es
pública por definición —viaja en la misma fila que el digest— así que quien tiene el volcado
tiene la sal, y con 16 bits de salida el barrido sigue siendo corto: **6 243 intentos** en vez
de 66 896. Diez veces más trabajo, sobre un espacio diez mil veces menor de lo necesario.

La sal arregló el síntoma que el informe nombraba. El defecto era otro.

## El remedio

```python
digest = hashlib.pbkdf2_hmac("sha256", clave.encode(), sal.encode(), ITERACIONES_CANONICO).hex()
return hmac.compare_digest(_digest_canonico(sal, clave), digest)
```

Digest **completo** —256 bits, no 16— con sal por cuenta y función de coste. Enumerar el
espacio deja de ser una estrategia y la comparación es de tiempo constante. La propiedad que
importa no es «tiene sal»: es **cuántos valores hay que probar**.

Se usa `pbkdf2_hmac` y no `scrypt` por una razón medida, no por gusto: `scrypt` es biblioteca
estándar pero **no está en toda instalación** (`hasattr(hashlib, "scrypt")` → `False` en el
Python que acompaña a macOS), y la regla 2 de este repositorio dice que no hay nada que
instalar. Una cápsula que necesita una biblioteca opcional no es autocontenida.

## Matriz medida

| sujeto | vía 1 · tabla | vía 2 · segundo preimagen | control legítimo | RC |
|---|---|---|---|---|
| `app_vulnerable.py` | **ABIERTA** (2/2, 57 225 digests) | **ABIERTA** (66 896 intentos) | ok | **0** |
| `patch_secure.py --naive` | BLOQUEADA (0/2) | **ABIERTA** (6 243 intentos) | ok | **0** |
| `patch_secure.py` | BLOQUEADA (0/2) | BLOQUEADA (sin colisión en 120 000) | ok | **1** |
| sujeto que niega todo | BLOQUEADA | BLOQUEADA | **NO** | **3** |

```bash
python3 exploit_poc.py                                  # 0  el sujeto cae por las dos vías
python3 exploit_poc.py --app patch_secure.py --naive    # 0  el ingenuo cae por la vía 2
python3 exploit_poc.py --app patch_secure.py            # 1  el canónico aguanta (≈0,9 s)
```

El control corre dentro de la misma corrida: si el sujeto no admite ni la clave real de una
cuenta que él mismo registró, sale RC `3` — rompió, no cerró. Comprobado con un sujeto que
niega toda credencial: cierra las dos vías y aun así **no** se lleva el `1`.

## Frontera: qué NO demuestra

- **No mide el coste del canónico.** La vía 2 se agota en 120 000 intentos porque lo que se mide
  es una ventana acotada, no los 2^256 valores del digest completo. Que el canónico
  aguante ahí prueba que el espacio dejó de caber en una corrida; **no** cuantifica cuánto
  costaría un ataque offline en serio.
- **No mide filtraciones de tiempo.** El canónico usa `compare_digest`, pero esta cápsula no
  mide tiempos: sería un reloj, y la regla 1 prohíbe el reloj como entrada.
- **La sal del ingenuo se deriva del usuario** para que la corrida sea determinista. Con sal
  aleatoria el resultado de la vía 2 no cambia: el ataque lee la sal del volcado, igual que
  lo haría un atacante. La derivación es una concesión al determinismo, no una ventaja del
  ataque.
- **No es un escáner.** Hay dos vectores. Un tercero fuera de esta lista puede seguir abierto
  y el RC `1` no lo desmiente.

## Origen

Caso propio, escrito desde cero, sin servidor ni dependencias. La referencia externa es la
categoría pública **OWASP A02:2021 — Cryptographic Failures**.

MIT. Ver [../LICENSE](../LICENSE).
