# 009 · Digest truncado a cuatro hex, con sal y todo

invariante: estado
falsador: cuelga

Un servicio guarda credenciales. El informe dice «las claves se guardan sin sal, así que una
tabla precompartida las abre todas». El arreglo añade sal por cuenta, la sal funciona, el
informe se cierra — y el servicio sigue cayendo igual.

## La hipótesis, en una línea falsable

> Con el digest recortado a cuatro hex hay 65 536 valores posibles, así que el volcado de la
> tabla basta para entrar en cuentas **sin conocer sus claves**, y añadir sal no devuelve los
> bits que la truncación se llevó.

`exploit_poc.py` la falsa por código de salida, no por lo que imprime.

## Anatomía del fallo

```python
ALMACEN[usuario] = hashlib.md5(clave.encode()).hexdigest()[:4]
```

Cuatro hex son **16 bits**. El espacio de digests posibles tiene 65 536 valores, y un espacio
de 65 536 valores no es un secreto: es una tabla de búsqueda. `respaldo()` publica el volcado
tal como lo leería quien lo obtiene, y con el volcado a la vista el ataque deja de ser
criptografía y pasa a ser aritmética.

La clave de las cuentas cae, y la cápsula publica **cuánto** cae en vez de redondearlo:

1. **Un barrido abre cuentas sin sus claves.** Se enumeran candidatos `cand-0`, `cand-1`, … y cada
   uno se prueba contra **todas** las cuentas del volcado. En el vulnerable abre **1 de 2** dentro
   del presupuesto: `ana` en el candidato **66 896**; `beto` no aparece en 120 000. Lo que abre no
   es una tabla de claves conocidas: es que el espacio de digests **cabe en una corrida**.
2. **El espacio se mide, no se recorre.** La segunda vía no busca: **cuenta**. Con el digest
   recortado a cuatro hex hay `2**16 = 65 536` valores y el presupuesto es 240 000 sondas, así que
   **CABE**. Sobre el digest completo del canónico son `2**256` valores: **NO CABE**. Es una
   deducción aritmética sobre el volcado, y así se etiqueta.

La diferencia entre «no se abrió» y «no se intentó» es la que hace honesta esta cápsula, y por eso
los veredictos son tres y no dos: `ABIERTA` (corrió y abrió), `BLOQUEADA` (corrió hasta el
presupuesto y no abrió nada) y **`NO EJERCIDA`** (no cabe en el presupuesto, con el número medido
que lo dice).

## Por qué el parche ingenuo no cierra

El ingenuo hace exactamente lo que el informe pedía —sal por cuenta— y conserva la truncación:

```python
sal = _md5("sal:" + usuario)[:8]
digest = _md5(sal + clave)[:4]     # la sal entró; los 16 bits siguen ahí
```

La sal hace su trabajo y no se le regatea: una tabla precomputada contra el esquema sin sal **ya no
sirve**, hay que reconstruirla por cuenta. Lo que la sal **no** puede hacer es devolver entropía:

```
$ python3 exploit_poc.py --app patch_secure.py --naive
SUJETO: patch_secure.py (modo ingenuo)
  [ABIERTA] una enumeracion abre cuentas sin sus claves: 2/2 cuentas abiertas en 55930 sondas (una pasada, 49687 candidatos)
  [CABE] el espacio del digest cabe: 16 bits: 65536 valores, caben en 240000 sondas
  [CONTROL] las claves reales entran        -> si
  [CONTROL] una clave ajena no entra        -> si
EXPLOTADO: se abrio una cuenta sin conocer su clave
```

La sal es pública por definición —viaja en la misma fila que el digest— así que quien tiene el
volcado tiene la sal, y el barrido sigue abriendo **las dos** cuentas: `ana` en el candidato
**6 243**, `beto` en el **49 687**. Diez veces menos trabajo que el vulnerable, sobre un espacio
diez mil veces menor de lo necesario.

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

| sujeto | barrido (enumera) | espacio del digest (mide) | control legítimo | RC |
|---|---|---|---|---|
| `app_vulnerable.py` | **ABIERTA** — 1/2 en 186 896 sondas | **CABE** — 16 bits, 65 536 | ok | **0** |
| `patch_secure.py --naive` | **ABIERTA** — 2/2 en 55 930 sondas | **CABE** — 16 bits, 65 536 | ok | **0** |
| `patch_secure.py` | **NO EJERCIDA** — 2\*\*256 no cabe | **NO CABE** — 256 bits | ok | **1** |
| sujeto que niega todo | BLOQUEADA — 0/2 en 240 000 sondas | CABE (deducción) | **NO** | **3** |

```bash
python3 exploit_poc.py                                  # 0  abre 1 de 2 cuentas
python3 exploit_poc.py --app patch_secure.py --naive    # 0  abre 2 de 2
python3 exploit_poc.py --app patch_secure.py            # 1  no cabe en el presupuesto
```

El control corre dentro de la misma corrida: si el sujeto no admite ni la clave real de una
cuenta que él mismo registró, sale RC `3` — rompió, no cerró. Comprobado con un sujeto que
niega toda credencial: su barrido **no abre nada** y su espacio **CABE**, o sea que un lector
que sólo mirase esas dos etiquetas lo daría por bueno; el control lo pone en `3`. Ese sujeto
es [control_espacio.py](control_espacio.py) y `./verificar-capsulas.sh` lo corre en cada push.

## Frontera: qué NO demuestra

- **El canónico no se abre porque no se intentó, y eso está medido, no supuesto.** La etiqueta
  `NO EJERCIDA` publica `2**256` sondas contra un presupuesto de 240 000. La cápsula **no**
  afirma que el canónico resista un ataque offline real: afirma que su espacio no cabe en esta
  corrida. La línea `LIMITE:` lo repite en la propia salida para que nadie lea `RC 1` como una
  prueba de fortaleza.
- **La sal del ingenuo se deriva del usuario** para que la corrida sea determinista. Con sal
  aleatoria el resultado no cambia: el ataque lee la sal del volcado, igual que un atacante. La
  derivación es una concesión al determinismo, no una ventaja del ataque.
- **No mide filtraciones de tiempo.** El canónico usa `compare_digest`, pero esta cápsula no mide
  tiempos: sería un reloj, y la regla 1 prohíbe el reloj como entrada.
- **No mide el coste del canónico.** `pbkdf2_hmac` con 120 000 iteraciones se elige por ser
  biblioteca estándar; cuánto frena a una GPU no se mide aquí.
- **No es un escáner.** Hay dos vías. Una tercera fuera de esta lista puede seguir abierta y el
  RC `1` no lo desmiente.

## Origen

Caso propio, escrito desde cero, sin servidor ni dependencias. La referencia externa es la
categoría pública **OWASP A02:2021 — Cryptographic Failures**.

MIT. Ver [../LICENSE](../LICENSE).
