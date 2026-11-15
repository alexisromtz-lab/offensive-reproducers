# offensive-reproducers

[![capsulas](https://github.com/alexisromtz-lab/offensive-reproducers/actions/workflows/capsulas.yml/badge.svg)](https://github.com/alexisromtz-lab/offensive-reproducers/actions/workflows/capsulas.yml)

Laboratorios sintéticos de seguridad ofensiva. Cada cápsula es un fallo real,
reconstruido desde cero en código propio, con su exploit determinista y su parche.
Todo corre en menos de diez segundos, sin dependencias externas y sin red externa.

> **¿Tienes un servicio web o una API?** → [Trabajo sobre tu servicio](#trabajo-sobre-tu-servicio)

## Por qué existe

Un write-up de una sala de entrenamiento es una narración: se lee, se cierra la pestaña
y no deja nada ejecutable. Una cápsula es lo contrario — un sujeto que el lector corre,
rompe y luego arregla, y que decide por código de salida en vez de por opinión.

Cada pieza publica dos cosas inseparables: **el ataque** (`exploit_poc.py`) y **la
defensa** (`patch_secure.py`), de modo que el mismo exploit devuelve RC 0 contra el
servicio vulnerable y RC 1 contra el corregido. Una afirmación que no se puede refutar
con el mismo comando no se publica.

Ninguna cápsula reproduce el contenido de la plataforma donde se practicó la técnica: no
hay banderas, ni soluciones, ni recorridos, ni capturas. Lo que se publica es el patrón
técnico reconstruido sobre un entorno mínimo propio.

## Cápsulas

| # | Vector | Sujeto | Comando |
|---|--------|--------|---------|
| 001 | Confusión de algoritmo en JWT (RS256 → HS256) | [001-jwt-algorithm-confusion](001-jwt-algorithm-confusion/) | `python3 exploit_poc.py` |
| 002 | SSRF en un renderizador de URLs | [002-ssrf-pdf-renderer](002-ssrf-pdf-renderer/) | `python3 exploit_poc.py` |
| 003 | Deserialización insegura (ejecución de código) | [003-insecure-deserialization-rce](003-insecure-deserialization-rce/) | `python3 exploit_poc.py` |
| 004 | Autorización a nivel de objeto (IDOR) | [004-idor-object-authorization](004-idor-object-authorization/) | `python3 exploit_poc.py` |
| 005 | Escritura fuera del destino con el nombre del miembro (tar-slip) | [005-archive-path-traversal](005-archive-path-traversal/) | `python3 exploit_poc.py` |
| 006 | Inyección SQL en un contexto numérico (el comentario de bloque hace de espacio) | [006-sql-injection-numeric-context](006-sql-injection-numeric-context/) | `python3 exploit_poc.py` |
| 007 | CORS que refleja el origen del atacante (mencionar el dominio no es serlo) | [007-cors-origin-reflection](007-cors-origin-reflection/) | `python3 exploit_poc.py` |

## Contrato de cada cápsula

```
NNN-<vector>/
├── README.md           # hipótesis, anatomía del fallo, impacto y remedio
├── app_vulnerable.py   # servicio mínimo sintético, sólo biblioteca estándar
├── exploit_poc.py      # PoC determinista: RC 0 explota, RC 1 bloqueado, RC 3 sujeto roto
└── patch_secure.py     # corrección canónica + el parche ingenuo, para refutarlo
```

Seis reglas que se comprueban, no se prometen:

1. **Determinista.** Dos corridas, el mismo resultado. Sin reloj, sin azar, sin red externa.
   Las cápsulas que necesitan un servicio levantan uno efímero en `127.0.0.1` y lo apagan
   al terminar: el aislamiento es parte del sujeto, no una promesa.
2. **Autocontenida.** Sólo biblioteca estándar. Nada que instalar.
3. **Falsable.** El PoC decide por código de salida, no por lo que imprime.
4. **Dual.** La misma corrida contra el parche debe fallar de forma determinista.
5. **El cierre se gana, no se supone.** RC `1` sólo se emite cuando la cápsula completó sus
   vías **y** comprobó que el sujeto sigue respondiendo a la entrada legítima. Un sujeto que
   falla siempre —o que niega todo, incluido lo suyo— sale con RC `3`, no con `1`: un
   corrector roto y un corrector que cierra son cosas distintas, y confundirlas da verde
   al sujeto que peor funciona. `sujeto_roto.py` existe para que ese error no pueda volver.
6. **El parche ingenuo se refuta, no se ilustra.** `patch_secure.py` incluye una corrección
   que cierra el caso reportado y deja abierta la clase de fallo; `--naive` debe seguir
   explotando. Si esa variante también cerrara, la cápsula estaría vendiendo una refutación
   que no existe, y el verificador la marca como fallo en vez de absolverla.

## Verificar todo

Un solo comando comprueba las cuatro promesas en todas las cápsulas, y es el mismo que
corre el CI en cada push — el badge de arriba es su resultado, no una promesa:

```bash
./verificar-capsulas.sh
```

Cada cápsula se corre cuatro veces: contra el servicio vulnerable (RC 0), contra el parche
(RC 1), contra ese mismo parche en su variante ingenua —que debe **seguir cayendo** (RC 0)—
y contra `sujeto_roto.py` (RC 3). Los dos últimos son los que impiden el falso verde: un
parche que cierra sólo el caso reportado y deja abierta la clase de fallo se desenmascara
en el tercero, y un sujeto que falla siempre no puede ser absuelto con `1`.

Contra un clon en blanco, el 15-Nov-2026:

```
OK     001-jwt-algorithm-confusion/ (vulnerable=0 parche=1 ingenuo=0 roto=3)
OK     002-ssrf-pdf-renderer/ (vulnerable=0 parche=1 ingenuo=0 roto=3)
OK     003-insecure-deserialization-rce/ (vulnerable=0 parche=1 ingenuo=0 roto=3)
OK     004-idor-object-authorization/ (vulnerable=0 parche=1 ingenuo=0 roto=3)
OK     005-archive-path-traversal/ (vulnerable=0 parche=1 ingenuo=0 roto=3)
OK     006-sql-injection-numeric-context/ (vulnerable=0 parche=1 ingenuo=0 roto=3)
OK     007-cors-origin-reflection/ (vulnerable=0 parche=1 ingenuo=0 roto=3)

7/7 capsulas: ataque RC 0, parche RC 1, parche ingenuo RC 0, sujeto roto RC 3
OK     tabla del README: 7 filas, 7 directorios
```

Sin cápsulas el script falla en vez de salir en verde: un cero de inventario no es una
verificación. Y la tabla de arriba se coteja contra los directorios en la misma corrida:
una cápsula sin fila deja el anuncio corto y una fila sin cápsula promete lo que no existe;
las dos cosas fallan el comando igual que una cápsula roja.

## Trabajo sobre tu servicio

Este repositorio es la **muestra de método**, no el resultado. El resultado es la
revisión de tu servicio:

1. **Se lee el código y se nombra el fallo** con la ruta y la línea exactas, no con
   adjetivos.
2. **Se escribe el PoC que lo demuestra** contra tu versión, en código ejecutable.
3. **Se entrega el par rojo/verde**: el ataque que falla y el parche que lo cierra.

**Lo que no es.** No es un sello de auditoría ni una garantía de cobertura total. Un
informe que dice «no encontré nada relevante en este alcance» es un resultado posible,
y se entrega con el mismo detalle que uno con hallazgos.

**Contacto.** `alexis_romtz@hotmail.com` con el repositorio y el alcance que te
interesa; el correo está también en [mi perfil](https://github.com/alexisromtz-lab).
Se habla el alcance antes de que nadie pague nada. No pegues código de tu servicio en
un issue público: un issue sirve para abrir la conversación, no para el análisis.

## Licencia

MIT. Ver [LICENSE](LICENSE).
