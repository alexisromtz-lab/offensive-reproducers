# 001 · Confusión de algoritmo en JWT (RS256 → HS256)

Un servicio que valida tokens firma y verifica con RSA. Aun así acepta un token firmado
con HMAC **usando su propia clave pública como secreto**. La clave pública se publica:
por eso el fallo no necesita ninguna clave privada ni ninguna filtración.

- [app_vulnerable.py](app_vulnerable.py) — el verificador con el fallo.
- [exploit_poc.py](exploit_poc.py) — forja el token de administrador y decide por código de salida.
- [patch_secure.py](patch_secure.py) — lista blanca de algoritmos; incluye el modo ingenuo.

## Reproducir en menos de 10 segundos

```bash
git clone --depth 1 https://github.com/alexisromtz-lab/offensive-reproducers
cd offensive-reproducers/001-jwt-algorithm-confusion

python3 exploit_poc.py                                  # RC 0  · EXPLOTADO
python3 exploit_poc.py --app patch_secure.py --naive    # RC 0  · el parche ingenuo no basta
python3 exploit_poc.py --app patch_secure.py            # RC 1  · BLOQUEADO
```

Sin dependencias: sólo la biblioteca estándar de Python 3.9 o superior. Sin red, sin
servidor que levantar, sin estado entre corridas.

## Hipótesis

> Si el verificador elige el algoritmo de firma leyendo la cabecera del token y usa el
> mismo material de clave para todos los algoritmos, entonces un token que declare HMAC
> y esté firmado con la clave pública será aceptado como si lo hubiera emitido el
> servicio.

El PoC la falsa en tres sujetos distintos con el mismo comando. La tercera corrida —el
parche canónico— devuelve RC 1: ahí la hipótesis deja de sostenerse y por eso el parche
está demostrado.

## Anatomía del fallo

Dos decisiones independientes, inocentes cada una por separado:

1. **El algoritmo lo elige el token.** La cabecera no está firmada antes de decidir con
   qué verificarla: es el mismo problema del huevo y la gallina. Un verificador no puede
   preguntarle al atacante cómo quiere que lo verifiquen.
2. **Un solo material de clave para dos mundos.** RSA necesita una clave pública;
   HMAC necesita un secreto compartido. Si el código carga «la clave» una vez y la pasa
   a las dos ramas, la rama HMAC termina usando algo que todo el mundo conoce.

Juntas producen el efecto: el atacante escribe `{"alg":"HS256"}` y firma con la clave
pública. El servicio calcula el mismo HMAC con el mismo material y coincide.

El tercer intento del PoC —`alg=none`— es el hermano trivial del mismo error: el
verificador acepta un token sin firma porque la cabecera lo pide. Aparece aquí como
control, no como tesis: cerrarlo primero es exactamente el parche ingenuo que la
segunda corrida demuestra insuficiente.

## Impacto

Suplantación total de identidad en el servicio: el token forjado declara
`role: admin` sobre la cuenta de otro usuario. No hace falta fuerza bruta, ni
credenciales, ni acceso a la red interna: hace falta leer un endpoint público.

## Remedio canónico

En [patch_secure.py](patch_secure.py) el algoritmo deja de venir del token:

```python
ALGORITMOS_PERMITIDOS = frozenset({"RS256"})
...
if alg not in ALGORITMOS_PERMITIDOS:
    raise InvalidToken(f"algoritmo fuera de la lista blanca: {alg!r}")
```

No hay rama HMAC, así que la clave pública no puede convertirse en secreto de nadie. La
lista blanca es lo que hace la diferencia: con `estricto=False` el parche sólo rechaza
`alg=none`, conserva el material compartido y el PoC vuelve a entrar.

## Procedencia

Material propio. Este repositorio no contiene material de ninguna plataforma de
entrenamiento: ni salas, ni banderas, ni recorridos, ni capturas. El vector técnico y el
código se escribieron desde cero; la clave RSA es el vector de prueba público del
[RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), Apéndice A.2, y se puede auditar con
`openssl rsa -pubin -in pub.pem -noout -text`. La referencia externa es la categoría
pública **OWASP A02:2021 — Cryptographic Failures**.

```bash
python3 -c 'import app_vulnerable; print(app_vulnerable.public_pem())' > pub.pem
openssl rsa -pubin -in pub.pem -noout -text     # Public-Key: (2048 bit)
```
