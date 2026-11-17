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

| # | Vector | OWASP 2021 | Sujeto | Comando |
|---|--------|------------|--------|---------|
| 001 | Confusión de algoritmo en JWT (RS256 → HS256) | A02 | [001-jwt-algorithm-confusion](001-jwt-algorithm-confusion/) | `python3 exploit_poc.py` |
| 002 | SSRF en un renderizador de URLs | A10 | [002-ssrf-pdf-renderer](002-ssrf-pdf-renderer/) | `python3 exploit_poc.py` |
| 003 | Deserialización insegura (ejecución de código) | A08 | [003-insecure-deserialization-rce](003-insecure-deserialization-rce/) | `python3 exploit_poc.py` |
| 004 | Autorización a nivel de objeto (IDOR) | A01 | [004-idor-object-authorization](004-idor-object-authorization/) | `python3 exploit_poc.py` |
| 005 | Escritura fuera del destino con el nombre del miembro (tar-slip) | A01 | [005-archive-path-traversal](005-archive-path-traversal/) | `python3 exploit_poc.py` |
| 006 | Inyección SQL en un contexto numérico (el comentario de bloque hace de espacio) | A03 | [006-sql-injection-numeric-context](006-sql-injection-numeric-context/) | `python3 exploit_poc.py` |
| 007 | CORS que refleja el origen del atacante (mencionar el dominio no es serlo) | A05 | [007-cors-origin-reflection](007-cors-origin-reflection/) | `python3 exploit_poc.py` |
| 008 | Cupón de un solo uso que nunca cuenta sus usos (la regla existe sólo como texto) | A04 | [008-insecure-design-coupon-ledger](008-insecure-design-coupon-ledger/) | `python3 exploit_poc.py` |
| 009 | Digest truncado a cuatro hex (la sal cierra el informe, no el fallo) | A02 | [009-truncated-hash-salt](009-truncated-hash-salt/) | `python3 exploit_poc.py` |
| 010 | La validación acepta lo que su propia serialización no devuelve (`inf` que se guarda `null`) | A08 | [010-serialization-validation-asymmetry](010-serialization-validation-asymmetry/) | `python3 exploit_poc.py` |
| 011 | El registro pierde el evento que importa y la vigilancia lo da por registrado (falla abierto) | A09 | [011-logging-fail-open](011-logging-fail-open/) | `python3 exploit_poc.py` |
| 013 | La credencial cambia y lo que la credencial vieja ya había emitido sigue entrando (la sesión y el «recordarme» sobreviven) | A07 | [013-session-survives-credential-change](013-session-survives-credential-change/) | `python3 exploit_poc.py` |

**Cobertura OWASP Top 10 (2021): nueve de las diez categorías.** A01 cubierta por 004 y 005 · A02 por 001 y 009 · A03 por 006 · A04 por 008 · A05 por 007 · A07 por 013 · A08 por 003 y 010 · A09 por 011 · A10 por 002. Fuera queda A06 (componentes vulnerables y desactualizados), descartada por diseño: demostrarla exige una dependencia real con CVE real, y esta casa no instala dependencias. La tabla se coteja contra los directorios en `./verificar-capsulas.sh`; esta línea se mide con
`grep -hoE 'A(0[0-9]|10):2021' */README.md | sort -u`.

La numeración salta de 011 a 013: el sujeto de 013 nació con otro nombre de directorio y se renumeró
antes de publicarse en vez de renumerar un directorio ya citado. El hueco es de nombre, no de
cápsula: no hay una 012 pendiente.

## Contrato de cada cápsula

```
NNN-<vector>/
├── README.md           # hipótesis, anatomía del fallo, impacto y remedio
├── app_vulnerable.py   # servicio mínimo sintético, sólo biblioteca estándar
├── exploit_poc.py      # PoC determinista: RC 0 explota, RC 1 bloqueado, RC 3 sujeto roto
└── patch_secure.py     # corrección canónica + el parche ingenuo, para refutarlo
```

Nueve reglas que se comprueban, no se prometen:

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
7. **El oráculo no se cree el rechazo.** Una cápsula cuyo PoC mira estado se corre también
   contra `parche_mentiroso.py`, un sujeto que hace el daño y **después** lanza la excepción
   declarada. `RC 0` ahí significa que el PoC vio el efecto pese a la mentira; `RC 1`
   significa que se la creyó. Las cápsulas cuyo efecto es el valor de retorno no pueden
   auditarse así, y lo declaran en vez de callarlo: `invariante: retorno` ·
   `falsador: fuera-de-alcance`.
8. **La declaración se coteja, no se decora.** `invariante:` y `falsador:` no son dos
   etiquetas: son la misma afirmación dicha dos veces, porque `fuera-de-alcance` **se define**
   como «el efecto es el valor de retorno… no hay estado que mirar». Una cápsula que declare
   `invariante: retorno` con `falsador: verifica` está afirmando que su PoC mira el estado y
   que no hay estado que mirar; el verificador la pone roja (`PAREJA`) en vez de absolverla.
   Ese cotejo también tiene lector: `./verificar-capsulas.sh --self-test` planta la
   contradicción en un directorio temporal, exige el rojo, la deshace y exige el verde.
9. **La frontera se mide, no se cree.** `falsador: fuera-de-alcance` afirma que el PoC no
   necesita ningún libro que mirar. Eso era una promesa: el 17-Nov-2026 se midió corriendo
   cada PoC en una jaula temporal y cotejando su árbol de archivos antes y después —cinco
   cápsulas, cero residuo—, y desde entonces lo comprueba el gate. Una cápsula que declara no
   tener libro y escribe uno se nombra `FRONTERA` y se pone roja: es el falso verde en la
   dirección peligrosa, porque lo que el lector cree que el PoC no toca, ya lo tocó.

## Verificar todo

Un solo comando comprueba las nueve promesas en todas las cápsulas, y es el mismo que
corre el CI en cada push — el badge de arriba es su resultado, no una promesa:

```bash
./verificar-capsulas.sh             # las nueve reglas sobre todas las cápsulas
./verificar-capsulas.sh --self-test # la pareja y la frontera se falsan a sí mismas
```

Cada cápsula se corre cuatro veces: contra el servicio vulnerable (RC 0), contra el parche
(RC 1), contra ese mismo parche en su variante ingenua —que debe **seguir cayendo** (RC 0)—
y contra `sujeto_roto.py` (RC 3). Los dos últimos son los que impiden el falso verde: un
parche que cierra sólo el caso reportado y deja abierta la clase de fallo se desenmascara
en el tercero, y un sujeto que falla siempre no puede ser absuelto con `1`.

La quinta: cada `control_*.py` que una cápsula declara se corre y debe dar **RC 3**. Ahí
viven las promesas que el README de esa cápsula escribe con palabras —«un error interno no
es un cupón cerrado» (008), «una deducción no es una apertura» (009), «un asiento que no
existe no es un asiento bloqueado» (010), «un servicio que no opera no pierde rastro»
(011)—, de modo que si dejaran de cumplirse el comando se
pone rojo en vez de seguir contando la historia.

La sexta: si el README de la cápsula declara `falsador: verifica`, el PoC se corre contra
`parche_mentiroso.py` y debe dar **RC 0**. Un `invariante:` o un `falsador:` ausente, o con
un valor que el verificador no conozca, es fallo; la única forma de saltarse esta prueba es
declararlo por escrito y que el lector lo cuente como lo que es. La séptima coteja la
**pareja**: `invariante:` y `falsador:` son la misma afirmación, así que `retorno` con
`verifica` —o `estado` con `fuera-de-alcance`— se nombra `PAREJA` y se pone roja, porque
declarar que el PoC mira el estado y que no hay estado que mirar no es una cápsula débil: es
una contradicción. La octava la cierra el cotejo de la tabla de arriba contra los directorios
que existen: una cápsula sin fila, o una fila sin cápsula, también se pone roja. La novena
mide la frontera en vez de creerla: si una cápsula declara `fuera-de-alcance`, su PoC corre en
una jaula y el árbol de archivos se coteja antes y después; escribir algo ahí es `FRONTERA` y
es rojo.

Y una regla que el PoC cobra antes de que el gate la vea: **sin `--naive`, todas las vías
tienen que coincidir.** Un veredicto que satisface a una sola esconde la regresión de la
otra —la vía que se cree el rechazo quedaría certificada por lo que hizo su vecina—, así que
el PoC sale con **RC 4** y lo nombra. Sólo el sujeto `--naive` puede mezclar, porque mezclar
es exactamente lo que declara: cierra el caso reportado y deja abierta la clase.

Contra un clon en blanco, el 17-Nov-2026:

```
OK     001-jwt-algorithm-confusion/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=n/a falsador=fuera-de-alcance+medido)
OK     002-ssrf-pdf-renderer/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=n/a falsador=fuera-de-alcance+medido)
OK     003-insecure-deserialization-rce/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=n/a falsador=no-medido)
OK     004-idor-object-authorization/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=n/a falsador=roto)
OK     005-archive-path-traversal/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=n/a falsador=verifica)
OK     006-sql-injection-numeric-context/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=n/a falsador=fuera-de-alcance+medido)
OK     007-cors-origin-reflection/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=n/a falsador=fuera-de-alcance+medido)
OK     008-insecure-design-coupon-ledger/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=3 falsador=fuera-de-alcance+medido)
OK     009-truncated-hash-salt/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=3 falsador=cuelga)
OK     010-serialization-validation-asymmetry/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=3 falsador=verifica)
OK     011-logging-fail-open/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=3 falsador=verifica)
OK     013-session-survives-credential-change/ (vulnerable=0 parche=1 ingenuo=0 roto=3 control=3 falsador=verifica)

12/12 capsulas: ataque RC 0, parche RC 1, parche ingenuo RC 0, sujeto roto RC 3
4/12 capsulas declaran 'falsador: verifica' y su PoC no se cree un rechazo declarado;
el resto publica su censo en el README (fuera-de-alcance · no-medido · cuelga · roto).
5/12 declaran 'falsador: fuera-de-alcance' y su PoC se midio en jaula: 0 con residuo.
cero residuo = la frontera se comprobo en esta corrida; no es una promesa del README.
7/12 declaran 'invariante: estado' (el falsificador tiene libro que mirar) y
5/12 'invariante: retorno' (el efecto es el valor de retorno): pareja cotejada con 'falsador:' en esta corrida.
OK     tabla del README: 12 filas, 12 directorios
```

Sin cápsulas el script falla en vez de salir en verde: un cero de inventario no es una
verificación. Y la tabla de arriba se coteja contra los directorios en la misma corrida:
una cápsula sin fila deja el anuncio corto y una fila sin cápsula promete lo que no existe;
las dos cosas fallan el comando igual que una cápsula roja.

## El oráculo también se mide

Un PoC que sólo mira la excepción no distingue un parche que cierra de un parche que
**finge** cerrar. El segundo hace el daño y después lanza la excepción declarada —«entrada
rechazada»—, y un PoC que se cree el rechazo publica `BLOQUEADO` sobre un archivo ya escrito.
Ese verde está en la dirección peligrosa: tranquiliza al lector sobre un sujeto intacto.

`parche_mentiroso.py` es ese sujeto. Primero consulta a `patch_secure` —el testigo de «esta
entrada se rechaza»— y, si la entrada se rechaza, ejecuta igual el código vulnerable y
después lanza la excepción declarada:

```bash
cd 010-serialization-validation-asymmetry
python3 exploit_poc.py --app ../parche_mentiroso.py   # RC 0 = el PoC no se cree el rechazo
```

La asimetría la usa el falsificador, no el PoC: el falsificador necesita saber cuál es el
ataque, el PoC no. Por eso el PoC sólo cambia cuando su oráculo no mira el estado.

**La lectura es de dos valores, no de un porcentaje.** `RC 0` significa que el PoC detectó el
efecto pese al rechazo declarado. `RC 1` significa que se lo creyó. Un `RC 1` con
`[FALSADOR] rechazos fingidos=0` **no es un veredicto**: el falsificador no llegó a mentir y
lo que se midió fue su alcance, no el oráculo.

### El censo, con cinco estados

Un `0` de intentos no es un cero de hallazgos. Ninguna cápsula se publica como «segura»: se
publica el estado que la corrida permite afirmar. Cada README declara dos líneas —qué mira su
PoC y qué dio el censo— y `./verificar-capsulas.sh` las lee:

| estado | qué mide | cápsulas |
|---|---|---|
| `verifica` | el PoC mira el libro después del rechazo y ve el efecto igual | 005 · 010 · 011 · 013 |
| `fuera-de-alcance` | el efecto **es** el valor de retorno que el falsificador descarta al lanzar: no hay estado que mirar, ni sano ni engañado | 001 · 002 · 006 · 007 · 008 |
| `no-medido` | el testigo no declaró ningún rechazo que falsificar (0 fingidos) | 003 |
| `roto` | el falsificador altera el sujeto hasta romperlo (RC 3) | 004 |
| `cuelga` | el falsificador no termina sobre ese sujeto | 009 |

El hallazgo estructural es la columna `invariante`, y es lo que hace el catálogo auditable sin
ejecutarlo: **si el invariante de una cápsula es de retorno, un parche que miente es
inauditable por construcción** —la mentira no deja huella— y eso no es una tarea pendiente,
es una frontera del instrumento. Si el invariante es de **estado**, el falsificador tiene algo
que mirar y la cápsula puede certificarse.

Esa frontera se declaraba y no se cotejaba. Hasta el 17-Nov-2026 el verificador leía las dos
líneas, validaba su vocabulario y las daba por buenas **por separado**: una cápsula con
`invariante: retorno` y `falsador: verifica` salía con RC `0` —medido con la contradicción
plantada en un directorio temporal antes de escribir el cotejo—, es decir, el catálogo
certificaba a la vez «mi PoC mira el estado» y «no hay estado que mirar». Hoy la pareja es la
séptima regla y `--self-test` la falsa en cada push: sin ese modo, el cotejo sería otra marca
sin lector y nadie sabría si sigue mirando.

Esa frontera se publicó de las dos direcciones. `005` y `010` estaban **engañadas** el
16-Nov-2026: las dos tenían la comprobación de estado escrita y no la consultaban dentro del
`except`. En `010` eran tres líneas (`frontera.asiento` y `frontera.puede` ya existían); en
`005` el veredicto pasó a darlo el sistema de archivos y la excepción quedó como testigo. Hoy
las cuatro cápsulas de estado se certifican, y el gate corre el falsificador en cada push: si
alguien devuelve un `except` que se cree el rechazo, el comando se pone rojo.

Y la frontera misma dejó de ser una promesa. El 17-Nov-2026 se midió el residuo de las cinco
cápsulas `fuera-de-alcance` corriendo cada PoC en una jaula y cotejando su árbol de archivos
antes y después: **cero residuo en las cinco**. El dato importa porque reencuadra el censo. Se
creía que el `fuera-de-alcance` no se podía medir; lo que no se había hecho era medirlo. Desde
entonces el gate lo mide en cada corrida y lo publica (`fuera-de-alcance+medido`): declarar que
no hay libro que mirar y escribir uno es `FRONTERA` y es rojo. La medición se toma sobre el
estado **prístino**, antes de que la corrida toque la cápsula: tomada después, la foto «antes»
ya incluiría lo que el propio PoC acaba de escribir y el residuo sería invisible —el falso
verde que la regla existe para cazar, cometido por la regla misma. Ese error se cometió y se
corrigió en la misma tarde, y por eso `--self-test` tiene un segundo brazo que planta un PoC
que escribe y exige el rojo.

`013` añade una lección que las otras tres no dieron: **el lector de estado puede estar mal elegido
y acusar al parche que cierra.** La lectura natural de su falla —mirar la marca `revocada` en el
registro— da `[A CIEGAS]` también contra el parche bueno, porque el parche canónico no revoca nada:
invalida por comparación de credencial. Un oráculo así produce un falso rojo, que es el error que no
bloquea ninguna entrega y por eso nadie corrige. Lo que separa a los dos lectores no es el fervor
—es haber corrido el oráculo contra el sujeto que debe absolver— y la cápsula lo publica medido en
su propio README.

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
