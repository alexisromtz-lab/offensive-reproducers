# 003 · Deserialización insegura con ejecución de código

Un servicio guarda la sesión en el cliente: recibe el estado ya serializado y lo restaura
al volver. No comprueba quién lo escribió ni que el formato sea el suyo. El cliente no
envía datos — envía instrucciones, y `pickle` obedece.

- [app_vulnerable.py](app_vulnerable.py) — el restaurador que confía en el token.
- [exploit_poc.py](exploit_poc.py) — cinco tokens hostiles, cinco vías, decide por código de salida.
- [patch_secure.py](patch_secure.py) — JSON + HMAC-SHA256 verificado antes de parsear + esquema cerrado; incluye el modo ingenuo.

## Reproducir en menos de 10 segundos

```bash
git clone --depth 1 https://github.com/alexisromtz-lab/offensive-reproducers
cd offensive-reproducers/003-insecure-deserialization-rce

python3 exploit_poc.py                                  # RC 0  · EXPLOTADO (5 de 5 vías)
python3 exploit_poc.py --app patch_secure.py --naive    # RC 0  · el parche ingenuo no basta (4 de 5)
python3 exploit_poc.py --app patch_secure.py            # RC 1  · BLOQUEADO (0 de 5)
```

Sin dependencias: sólo la biblioteca estándar de Python 3.9 o superior. Sin red, sin disco,
sin reloj: los cinco tokens se construyen y se consumen en el mismo proceso.

> Esta cápsula ejecuta código a propósito, porque ése es el fallo. Cada token lo genera el
> propio PoC; no le pases tokens que no hayas construido tú.

## Hipótesis

> Si el servicio restaura estado de sesión con un deserializador que puede nombrar
> funciones, entonces el token es un programa y ninguna lista negra de nombres lo detiene:
> el nombre es cualquiera que sea importable. La única frontera que funciona es la
> integridad —firmar y verificar antes de parsear— más un formato que no sepa nombrar
> funciones.

El PoC la falsa en tres sujetos distintos con el mismo comando. La tercera corrida —el
parche canónico— devuelve RC 1: ahí la hipótesis deja de sostenerse y por eso el parche
está demostrado.

## La sonda: por qué el marcador no es un `print`

El PoC registra en `sys.modules` un módulo propio, `lab003_sonda`, con una función
`marca()`. Un `GLOBAL` de pickle nombra un módulo y un atributo cualesquiera; si el sujeto
lo resuelve y lo llama, el valor de retorno es la marca. La prueba es que el sujeto
**devolvió** algo que sólo pudo producir ejecutando lo que el flujo decía. No toca el disco,
ni la red, ni lanza un proceso.

## Las cinco vías

| vía | qué demuestra | el parche ingenuo |
|-----|---------------|-------------------|
| `builtins.eval` con `__import__('os')` | el gadget de libro, el que toda lista negra enumera | lo bloquea |
| `builtins.eval` con la sonda | la misma capacidad, sin ninguna palabra que listar | pasa |
| `importlib.import_module` | importar sin deletrear `import` | pasa |
| `lab003_sonda.marca` directo | el nombre del `GLOBAL` es arbitrario: una lista finita no lo cubre | pasa |
| `rol: admin` sin código | el fallo no es «una función peligrosa», es confiar en el estado del cliente | pasa |

Las vías 2, 3 y 4 comparten un mismo punto ciego —la lista negra enumera *palabras*, no
*capacidades*— y se publican separadas porque cada una nombra una forma distinta de
esquivarla. La quinta no necesita código: aunque el deserializador fuese seguro, el
servicio seguiría aceptando un rol que nunca emitió.

## Anatomía del fallo

Dos decisiones independientes, inocentes cada una por separado:

1. **El formato del cliente es el formato del servidor.** `pickle` tiene una instrucción
   (`REDUCE`) cuyo significado es «llama a esto con estos argumentos». Aceptar un flujo de
   `pickle` de la red es aceptar un programa.
2. **Nadie pregunta quién escribió el token.** Sin firma, no hay diferencia entre un estado
   que emitió el servidor y uno que redactó el atacante. Las vías 1 a 4 explotan la
   primera decisión; la quinta explota la segunda sin tocar la primera.

## Impacto

Ejecución de código en el proceso del servidor con sus credenciales: lectura de la base de
datos, pivoteo a la red interna, y persistencia. Escalada de privilegios cuando el rol
viaja en el token. El atacante no necesita romper ninguna autenticación: se le entrega el
objeto que el servidor va a ejecutar.

## Remedio canónico

En [patch_secure.py](patch_secure.py):

```python
firma, separador, cuerpo = token.partition(SEPARADOR)
if not hmac.compare_digest(firma, _firmar(cuerpo)):
    raise FirmaInvalida("la firma no corresponde al cuerpo")
estado = json.loads(cuerpo.decode("utf-8"))
_validar_esquema(estado)
```

Cuatro decisiones, y ninguna sobra:

- **JSON en lugar de `pickle`**, porque un formato de datos no tiene manera de nombrar una
  función. El fallo desaparece del espacio de representaciones, no de una lista.
- **Verificar la firma antes de mirar el contenido**, con `hmac.compare_digest` y en tiempo
  constante. El orden importa: parse-then-verify ya ejecutó.
- **Esquema cerrado**: campos exactos, tipos exactos —`type(x) is int` y no
  `isinstance(x, int)`, porque `True` pasa por entero— y valores admitidos.
- **La autoridad no viaja en el token**: `admin` no está en `ROLES`. `autorizar()` no
  cambió; lo que cambió es que ya no puede llegarle un rol que el servidor no emitió.

### El parche ingenuo

`--naive` deja `pickle` donde está y busca palabras peligrosas en los bytes del flujo
(`posix`, `nt.`, `system`, `subprocess`, `popen`, `os`). Medido, el PoC lo deja en 4 de 5
vías, y el control del propio PoC muestra los dos defectos de una búsqueda por subcadena:

- **falso negativo**: el GLOBAL `lab003_sonda.marca` no contiene ninguna de esas palabras y
  se ejecuta igual;
- **falso positivo**: un token legítimo cuyo usuario se llama `costa.rivera` se rechaza,
  porque `costa` contiene `os`. Un filtro que rompe tráfico bueno no se puede desplegar, y
  el que se despliega acaba vaciándose hasta no bloquear nada.

Además, el ingenuo acepta su propio token alterado (`lector` → `editor`): no tiene
integridad, sólo tiene una lista.

## Procedencia

Material propio. Este repositorio no contiene material de ninguna plataforma de
entrenamiento: ni salas, ni banderas, ni recorridos, ni capturas. El servicio, el
serializador, la sonda, el exploit y el parche se escribieron desde cero para esta cápsula.
La clave HMAC es de laboratorio y está escrita en el código a propósito, para que la
cápsula corra sin configuración; en un despliegue real no viaja en el repositorio. La
referencia externa es la categoría pública **OWASP A08:2021 — Software and Data Integrity
Failures**.
