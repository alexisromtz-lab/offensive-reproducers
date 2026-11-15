# 007 · CORS que refleja el origen del atacante

Una API que autentica por cookie devuelve las cabeceras CORS del origen que le llega. El
navegador obedece: `Access-Control-Allow-Origin: <origen del atacante>` junto a
`Access-Control-Allow-Credentials: true` significa que el sitio del atacante **lee la
respuesta autenticada de la víctima** desde su propio dominio.

## La hipótesis, en una línea falsable

> Hay un origen que no es nuestro que recibe sus propias cabeceras con credenciales, y no
> necesita ni un dominio propio ni un servidor: basta con mencionar el nuestro.

`exploit_poc.py` la falsa por código de salida, no por lo que imprime.

## Anatomía del fallo

```python
return {"Access-Control-Allow-Origin": origen, "Access-Control-Allow-Credentials": "true"}
```

Reflejar el origen es el atajo que hace funcionar el frontend en local sin configurar nada.
Es también la forma de desactivar CORS por completo: la cabecera deja de distinguir quién
pregunta, y con credenciales el navegador entrega la sesión.

El sujeto no levanta servidor. Es **una función pura de cabeceras**, así que lo que se mide
es el criterio y no el transporte — y la corrida es determinista sin red.

## Por qué el parche ingenuo no cierra

El informe dice «la API refleja orígenes ajenos». El arreglo que se reporta deja de reflejar
y comprueba que el dominio propio **aparezca** en la cadena:

```python
permitido = "tiendaplatino.com.mx" in origen
```

Y funciona: `--naive` bloquea `https://evil.example`. Pero confunde *hablar de mi dominio*
con *ser mi dominio*:

```
https://app.tiendaplatino.com.mx.evil.example
                                 ^^^^^^^^^^^^ el host real es evil.example
```

El atacante no necesita comprar un subdominio: le basta registrar un dominio cuyo nombre
contenga el nuestro. Comparar por subcadena autoriza a quien menciona; comparar por origen
completo autoriza a quien es.

## El remedio

```python
ORIGENES_PERMITIDOS = frozenset({"https://app.tiendaplatino.com.mx"})
permitido = origen in ORIGENES_PERMITIDOS
```

Un origen es un valor finito —esquema, host y puerto— y se compara entero o no se compara.
Sin lista que adivinar, sin subcadena que valga.

## Matriz medida

| sujeto | origen ajeno | dominio como subcadena | origen legítimo | RC |
|---|---|---|---|---|
| `app_vulnerable.py` | FILTRA | FILTRA | admitido | **0** |
| `patch_secure.py --naive` | BLOQUEADA | **FILTRA** | admitido | **0** |
| `patch_secure.py` | BLOQUEADA | BLOQUEADA | admitido | **1** |

```bash
python3 exploit_poc.py                                  # 0  el sujeto cae
python3 exploit_poc.py --app patch_secure.py --naive    # 0  el ingenuo también
python3 exploit_poc.py --app patch_secure.py            # 1  el canónico aguanta
```

El control corre dentro de la misma corrida: si el sujeto niega también el origen legítimo,
sale RC `3` — rompió, no cerró.

## Frontera: qué NO demuestra

- **No cubre el servidor**: mide la cabecera, no si el backend además valida la cookie contra
  `Origin`. Una API con CORS perfecto y CSRF abierto sigue siendo explotable por otra vía.
- **No mide preflight**: sólo la respuesta simple. `OPTIONS` y `Access-Control-Allow-*` para
  métodos no simples son otro sujeto.
- **No es un escáner**: hay dos vectores. Un tercero fuera de esta lista puede seguir abierto
  y el RC `1` no lo desmiente.

## Origen

Caso propio, escrito desde cero, sin servidor ni dependencias. La referencia externa es la
categoría pública **OWASP A05:2021 — Security Misconfiguration**.

MIT. Ver [../LICENSE](../LICENSE).
