# 006 · Inyección SQL en un contexto numérico

Un buscador de cuentas por `id`. El id es un entero, así que nadie lo entrecomilla — para qué,
si un entero no lleva comillas. Esa frase, que suena a razón, es el fallo entero: el valor se
concatena crudo en el `WHERE`, y una columna entera acepta texto si ese texto es SQL.

## La hipótesis, en una línea falsable

> Existe una entrada que devuelve una cuenta **cuya clave no se conoce**, y esa entrada no
> necesita ni una comilla ni una palabra prohibida.

`exploit_poc.py` la falsa por código de salida, no por lo que imprime.

## Anatomía del fallo

```sql
SELECT usuario, marca FROM cuentas WHERE id = {entrada_id} AND clave = '{clave}'
```

La clave sí está entrecomillada, así que el reflejo —escapar comillas— se aplica donde no hacía
falta. El id no lleva comillas porque "es un número": no hay nada que escapar, y por eso el
ataque no las usa.

## Por qué el parche ingenuo no cierra

El arreglo que se reporta en el ticket rechaza `" or "` y `"--"`. Literalmente el del informe. Y
funciona: `--naive` bloquea la vía clásica. El problema es de especie, no de grado: **una lista
negra enumera grafías**, y el lenguaje tiene más grafías que la lista.

En SQLite `/**/` separa tokens igual que un espacio. `0/**/or/**/1=1/**/or/**/1=1` no contiene
ni `" or "` ni `"--"`, y el motor lee:

```sql
WHERE id = 0 OR 1=1 OR 1=1 AND clave = 'intruso'
```

Hacen falta **los dos** `or`. El primero anula `id = 0`; el segundo deja un `1=1` suelto que no
depende de la clave. Con uno solo, el `AND clave` se pega al segundo término y la condición vuelve
a ser falsa — el ataque de dos términos devuelve cero filas y parece que el filtro sirvió.

## El remedio

Que la entrada deje de ser SQL:

```python
con.execute("SELECT usuario, marca FROM cuentas WHERE id = ? AND clave = ?", (entrada_id, clave))
```

El motor trata el valor como dato, no como texto a interpretar. No queda lista que mantener ni
transformación que deshacer, y la consulta legítima sigue devolviendo lo suyo.

## Matriz medida

| sujeto | vía clásica | vía `/**/` | función | RC |
|---|---|---|---|---|
| `app_vulnerable.py` | FILTRA | FILTRA | intacta | **0** |
| `patch_secure.py --naive` | BLOQUEADA | **FILTRA** | intacta | **0** |
| `patch_secure.py` | BLOQUEADA | BLOQUEADA | intacta | **1** |

```bash
python3 exploit_poc.py                                  # 0  el sujeto cae
python3 exploit_poc.py --app patch_secure.py --naive    # 0  el ingenuo también
python3 exploit_poc.py --app patch_secure.py            # 1  el canónico aguanta
```

El código `3` existe para el cierre por rotura: un sujeto que bloquea las dos vías porque dejó de
responder a todo no ha arreglado nada. El PoC comprueba la función en la misma corrida.

## Frontera: qué NO demuestra

- **No mide la lectura del revisor**, mide el cierre del sumidero. Que alguien llegue al parche
  canónico leyendo o adivinando no es observable desde aquí.
- **No cubre el ORM**: si el sujeto arma SQL con un `order_by` que viene de la petición, el
  parámetro no salva el orden de las cláusulas. Es otro caso, con otro sumidero.
- **No es un escáner**: hay dos vectores, no un catálogo. Una entrada que no está aquí puede
  seguir abierta, y el RC 1 no lo desmiente.

## Origen

Caso propio, escrito desde cero sobre un entorno mínimo de `sqlite3`. No reproduce enunciados,
código ni explicaciones de ninguna plataforma de entrenamiento: la referencia externa es la
categoría pública **OWASP A03:2021 — Injection**.

MIT. Ver [../LICENSE](../LICENSE).
