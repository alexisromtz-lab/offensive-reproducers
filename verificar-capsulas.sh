#!/bin/sh
# Las promesas del README, comprobadas en un solo lugar: cada capsula da
# RC 0 contra el servicio vulnerable, RC 1 contra el parche, RC 0 contra ese
# mismo parche en su variante ingenua -que debe seguir cayendo-, RC 3 contra
# `sujeto_roto.py` y RC 3 contra cada `control_*.py` que la capsula declare. El CI
# corre este mismo script en cada push: si aqui no sale, el badge y el README mienten.
#
# La septima: `invariante:` y `falsador:` son la misma afirmacion dicha dos veces, y se
# cotejan. Y ese cotejo tambien tiene lector: `--self-test` planta la contradiccion en un
# directorio temporal y exige que el script se ponga rojo.
#
# La novena: `falsador: fuera-de-alcance` afirma que el PoC no necesita libro que mirar. Eso
# se mide, no se cree: el PoC corre en una jaula y su arbol de archivos se coteja antes y
# despues. Una capsula que declara no tener libro y escribe uno es un falso verde en la
# direccion peligrosa --lo que el usuario cree que no toca, ya lo toco--.
#
# La novena, corregida el 17-Nov-2026: su foto no alcanzaba donde el sujeto escribe por
# defecto. Medido en una jaula de sonda, un PoC que escapaba por `tempfile` y por `~` daba
# `0 con residuo` y la capsula salia `OK`: el gate publicaba salud sobre un cero de alcance.
# Ahora HOME, TMPDIR y los XDG se apuntan a subdirectorios de la propia jaula y la foto se
# toma sobre toda ella, asi que lo redirigible pasa a ser residuo medido. Ruta absoluta
# literal (`/tmp/x`, `/var`) y red siguen fuera: se declaran en el censo y no se cuentan cero.
#
# El alcance de ese arreglo, el 17-Nov-2026: el gate tiene tres puertas --la foto del residuo,
# el limite de segundos y el reloj movido-- y solo la primera pinchaba el entorno; las otras
# dos corrian con el HOME del host. Medido en una capsula de sonda bajo `limite:`, los dos
# archivos que su PoC escribia por `tempfile` y por `~` aparecieron en la maquina sin que
# ninguna jaula los viera. Ahora las tres pasan por `entorno_pinzado` --una lista de rutas, un
# solo alcance-- y el sexto brazo del `--self-test` lo falsa por conducta, con el entorno
# heredado como trampa y el mismo PoC sin jaula como control positivo.
#
# El censo de los brazos, el 17-Nov-2026: seis brazos se falsaban a si mismos, pero el numero
# seis vivia en el README y en ningun lector. Medido: borrar el brazo del entorno dejaba
# `--self-test` en RC 0 con un brazo menos, asi que «el instrumento se falsa a si mismo» era
# cierto con siete brazos y con uno. Un brazo ausente no deja residuo, solo silencio, y el
# silencio no es un cero: ahora el conjunto se declara por nombre y la corrida se coteja
# contra el a la salida. Un brazo que falta se nombra; uno que sobra, tambien.
#
# La decima: todo valor que el censo publica tiene lector. `no-medido`, `roto` y `cuelga`
# pasaban por un `;;` vacio mientras el censo los imprimia como datos. Desde el 17-Nov-2026
# se miden contra el mismo falsificador que los provoca: un vocabulario que crece sin lector
# es prosa con formato de dato.
#
# La undecima: el tiempo no es un tercer tipo de oraculo, es una dimension del sujeto. El
# tipo sigue siendo dos --que mira el juicio, estado o retorno--; el instante dice CUANDO se
# hace la pregunta. Una capsula que declara `reloj: AHORA` afirma que su sujeto pregunta la
# hora, y aqui se mueve el instante por donde el sujeto ya pregunta: si el veredicto no
# cambia, el campo decoraba. Medido el 17-Nov-2026 en la primera corrida: el fixture de 001
# caduca.
#
# La decimosegunda, la admision, el 17-Nov-2026: las once anteriores miden el alcance de un
# lector sobre lo ya admitido; ninguna media que se admitio. Medido con tres directorios de
# sonda: uno sin README salia nombrado con dos causas que no eran la suya --TIPO y `falsador:`
# no reconocido, para un archivo que no existe--; uno con `invariante:` dos veces salia OK
# llevando la contradiccion dentro, porque `head -1` lee la primera y la segunda es prosa; y uno
# sin `exploit_poc.py` se acusaba de «creerse el rechazo declarado». Los tres contaban en el
# denominador que el censo publica. Ahora la admision es una funcion con causa nombrada y la
# poblacion se escribe una sola vez: lo no admitido no entra al censo, y las fracciones se
# cuentan sobre esa lista y no sobre un segundo glob que puede discrepar de la primera.
#
# La decimotercera, lo publicado, el 17-Nov-2026: las doce anteriores miden lo que el gate
# comprueba; ninguna media lo que el repo anuncia. El bloque de resultados del README se habia
# cotejado a mano una vez --en el acto de la admision-- y ningun lector lo comparaba en cada
# push: editar una fraccion del script sin tocar el bloque dejaba el CI en verde con el
# escaparate publicando una cifra que ya no media. Lo mismo con las dos cifras que el bloque no
# contiene: cuantos brazos se falsan y cuantas reglas promete el contrato. Ahora las tres tienen
# lector en cada push, y el sujeto de la primera es la corrida entera --no un resumen de ella--
# por eso el decimo brazo corre el gate real en vez de copiar el arbol. Coste medido: 18,4 s.
#
# La decimocuarta, el contrato de la base, el 17-Nov-2026: las trece anteriores miden el alcance
# de un lector sobre lo admitido, que poblacion entro o lo que el repo anuncia. Ninguna media el
# certificado que el repo se firma a si mismo. `brazos.esperado` guarda la linea que cada brazo
# publica y `--escribir-base` es su unico escritor, sin contrato sobre el contenido: medido en
# una copia del arbol, un brazo degradado a «OK --self-test: hecho» fue bendecido y la corrida
# salio RC 0 con «conducta de 10 brazos identica». La base certificaba estabilidad, no fuerza: un
# brazo podia dejar de publicar la cifra de lo que mide y seguir contando como sano. Ahora cada
# fila de `contrato.esperado` declara el token que su linea verde tiene que publicar y el marcador
# que su FALLA tiene que imprimir; el undecimo brazo coteja los dos y `--escribir-base` ya no
# puede bendecir una linea que los pierda. Su limite, declarado: el contrato ata el certificado
# al texto, no a la ejecucion --un brazo vaciado por dentro que conserve la linea que publica su
# token pasa--; verlo exige un lector de conducta por brazo que este instrumento no tiene.
# Coste medido: 0,1 s, sin red y sin jaula.
set -u

# `falsador: cuelga` no deja codigo de salida, asi que su unica medida posible es un reloj.
# Medido el 17-Nov-2026: 009 no termina ni en 20 s; el limite se queda corto y se publica.
LIMITE_CUELGA=5
LIMITE_FALSADOR=8

# El instante con el que se mueve el reloj de una capsula que declara `reloj:`. Es un valor
# declarado y no el reloj real + N anios para que la corrida sea determinista: 4200000000 es
# enero de 2103, y cualquier fixture con fecha humana ya caduco. Se publica en el censo.
RELOJ_FUERA=4200000000

# Corre un comando con las rutas por defecto del sujeto (HOME, TMPDIR, TMP, TEMP y los XDG)
# apuntadas a subdirectorios de la casa que se le pasa. Es la unica definicion de esas rutas:
# si cada jaula llevara su propia lista, el gate tendria tres alcances y solo uno medido --que
# es exactamente lo que paso hasta el 17-Nov-2026, cuando solo residuo_en_jaula pinchaba y las
# otras dos puertas escribian con el HOME del host--.
entorno_pinzado() {
  _casa=$1
  shift
  mkdir -p "$_casa/home" "$_casa/tmp" || return 1
  env HOME="$_casa/home" TMPDIR="$_casa/tmp" TMP="$_casa/tmp" TEMP="$_casa/tmp" \
    XDG_CACHE_HOME="$_casa/home/.cache" XDG_CONFIG_HOME="$_casa/home/.config" \
    XDG_DATA_HOME="$_casa/home/.local/share" XDG_STATE_HOME="$_casa/home/.local/state" \
    XDG_RUNTIME_DIR="$_casa/tmp/run" "$@"
}

# Cuenta las lineas de diferencia entre el arbol de la jaula antes y despues de correr su PoC.
# La foto se toma sobre la jaula entera --no solo sobre el subdirectorio de la capsula-- y el
# PoC corre bajo entorno_pinzado: lo que escriba por `tempfile` o por `~` cae dentro de la foto.
# El limite que sigue declarado: una ruta absoluta literal (`/tmp/x`, `/var`, `/etc`) o una
# escritura por red no se ven aqui, y el censo lo publica como frontera, no como cero.
residuo_en_jaula() {
  cap=$1
  jaula=$(mktemp -d "${TMPDIR:-/tmp}/frontera.XXXXXX") || { echo 99; return 0; }
  # El libro del antes/despues vive FUERA de la jaula: dentro, la propia foto se veria a si
  # misma y toda capsula tendria residuo.
  libro=$(mktemp -d "${TMPDIR:-/tmp}/frontera-libro.XXXXXX") || { rm -rf "$jaula"; echo 99; return 0; }
  cp -R "${cap%/}" "$jaula/" || { rm -rf "$jaula" "$libro"; echo 99; return 0; }
  mkdir -p "$jaula/home" "$jaula/tmp" || { rm -rf "$jaula" "$libro"; echo 99; return 0; }
  sub="$jaula/${cap%/}"
  (cd "$jaula" && find . -type f ! -name '*.pyc' ! -path '*/__pycache__/*' | LC_ALL=C sort | xargs cksum) >"$libro/antes" 2>/dev/null
  (cd "$sub" && entorno_pinzado "$jaula" python3 exploit_poc.py >/dev/null 2>&1)
  (cd "$jaula" && find . -type f ! -name '*.pyc' ! -path '*/__pycache__/*' | LC_ALL=C sort | xargs cksum) >"$libro/despues" 2>/dev/null
  escrito=$(diff "$libro/antes" "$libro/despues" 2>/dev/null | grep -c '^[<>]')
  rm -rf "$jaula" "$libro"
  echo "${escrito:-99}"
}

# Corre el PoC de una capsula contra un sujeto con limite de segundos y publica
# "RC=<rc> FINGIDOS=<n>". El falsificador ya dice cuantos rechazos fingidos vio --con cero
# fingidos un RC 0 no absolvio nada-- y ese numero, que hasta el 17-Nov-2026 se tiraba a
# /dev/null, es lo que decide si su veredicto significa algo. El PoC corre bajo entorno_pinzado,
# asi que una escritura por `tempfile` o por `~` cae en la casa y no en el host. RC 124 si no
# termina y 99 si la casa no se pudo montar.
con_limite() {
  cap=$1
  sujeto=$2
  limite=$3
  casa=$(mktemp -d "${TMPDIR:-/tmp}/limite-casa.XXXXXX") || { echo "RC=99 FINGIDOS=0"; return 0; }
  entorno_pinzado "$casa" python3 - "$cap" "$sujeto" "$limite" <<'PY'
import subprocess, sys
cap, sujeto, limite = sys.argv[1], sys.argv[2], float(sys.argv[3])
try:
    r = subprocess.run(["python3", "exploit_poc.py", "--app", sujeto], cwd=cap,
                       capture_output=True, text=True, errors="replace", timeout=limite)
except subprocess.TimeoutExpired:
    print("RC=124 FINGIDOS=0")
    raise SystemExit(0)
fingidos = 0
for linea in (r.stdout or "").splitlines():
    if "rechazos fingidos=" in linea:
        fingidos = int(linea.split("rechazos fingidos=")[1].split()[0])
print("RC=%d FINGIDOS=%d" % (r.returncode, fingidos))
PY
  rm -rf "$casa"
}

# Corre el PoC con el instante movido y publica "RC=<rc>". El inyector viaja como
# `sitecustomize.py` en una jaula que hace de PYTHONPATH, asi que el sujeto pregunta la hora
# por el mismo camino que ya usaba y no se le toca una linea. Sin dormir y sin mock: se mueve
# la respuesta, no se espera. El PoC corre bajo entorno_pinzado --casa aparte de la jaula del
# inyector, para que un `.py` que escriba el sujeto no acabe en el PYTHONPATH--. RC 124 si no
# termina, 99 si la jaula no se pudo montar.
reloj_en_jaula() {
  cap=$1
  instante=$2
  limite=$3
  origen=$(cd "$(dirname "$0")" && pwd) || { echo "RC=99"; return 0; }
  jaula=$(mktemp -d "${TMPDIR:-/tmp}/reloj.XXXXXX") || { echo "RC=99"; return 0; }
  cp "$origen/inyector_reloj.py" "$jaula/sitecustomize.py" || { rm -rf "$jaula"; echo "RC=99"; return 0; }
  casa=$(mktemp -d "${TMPDIR:-/tmp}/reloj-casa.XXXXXX") || { rm -rf "$jaula"; echo "RC=99"; return 0; }
  entorno_pinzado "$casa" PYTHONPATH="$jaula" AHORA="$instante" \
    python3 - "$cap" "$limite" <<'PY'
import subprocess, sys
cap, limite = sys.argv[1], float(sys.argv[2])
try:
    r = subprocess.run(["python3", "exploit_poc.py"], cwd=cap,
                       capture_output=True, text=True, errors="replace", timeout=limite)
except subprocess.TimeoutExpired:
    print("RC=124")
    raise SystemExit(0)
print("RC=%d" % r.returncode)
PY
  rm -rf "$jaula" "$casa"
}

# El conjunto de brazos que el `--self-test` declara ejercer, por nombre. La lista se declara
# aqui y el cotejo vive al final de `self_test()`: borrar un brazo lo deja fuera de lo
# ejercido y el cotejo lo nombra. Declarar el numero en vez de los nombres no serviria --un
# brazo se puede sustituir por otro y el total no se mueve--.
#
# El nombre no basta, y se midio el 17-Nov-2026: un brazo vaciado por dentro --que conserva su
# apunte y su nombre-- pasaba el cotejo. Por eso cada brazo publica ademas su linea medida y
# el archivo `brazos.esperado` guarda la base fechada contra la que se coteja. Un cambio de
# conducta legitimo cambia la linea, y quien lo hace la reescribe con `--escribir-base` en el
# mismo acto: el cambio queda en el diff, que es donde un humano lo lee.
CENSO_BRAZOS="pareja frontera vocabulario tiempo alcance entorno censo conducta admision publicado contrato"

# Coteja lo ejercido contra lo declarado, dos listas de nombres separados por espacio. Publica
# cada diferencia con nombre propio y devuelve RC 1 si hay alguna. Es puro a proposito: recibe
# los dos conjuntos por argumento y no lee el script, para que el septimo brazo pueda falsarlo
# sin recursion --un brazo que corriera `--self-test` dentro de `--self-test` duplicaria el
# coste y mediria su propio reflejo--.
cotejar_censo() {
  python3 - "$1" "$2" <<'PY'
import sys
ejercidos = set(sys.argv[1].split())
declarados = set(sys.argv[2].split())
faltan = sorted(declarados - ejercidos)
sobran = sorted(ejercidos - declarados)
if faltan:
    print("FALLA  --self-test censo: el censo declara brazos que la corrida no ejercio: %s" % ", ".join(faltan))
if sobran:
    print("FALLA  --self-test censo: la corrida ejercio brazos que el censo no declara: %s" % ", ".join(sobran))
raise SystemExit(1 if (faltan or sobran) else 0)
PY
}

# Publica la linea del brazo y la apunta para el cotejo de conducta. Una sola fuente: el texto
# se escribe en el apunte al publicarse, no se repite, para que lo impreso y lo cotejado no
# puedan divergir por editar uno solo de los dos.
publicar_brazo() {
  printf '%s\n' "$2"
  printf '%s|%s\n' "$1" "$2" >> "$CONDUCTA_FICHERO"
}

# Coteja la conducta medida contra la base fechada, dos archivos de lineas `<brazo>|<texto>`.
# Nombra el brazo que no publico linea, el que publico otra y el que publica sin base, y
# devuelve RC 1 si hay alguno. Como `cotejar_censo`, es puro: recibe dos rutas y no invoca el
# `--self-test`, para que el octavo brazo pueda falsarlo sin recursion.
cotejar_conducta() {
  python3 - "$1" "$2" <<'PY'
import sys

def leer(ruta):
    pares = {}
    with open(ruta, encoding="utf-8") as f:
        for linea in f.read().splitlines():
            if not linea.strip():
                continue
            nombre, _, texto = linea.partition("|")
            pares[nombre.strip()] = texto
    return pares

medido = leer(sys.argv[1])
esperado = leer(sys.argv[2])
rc = 0
for nombre in sorted(esperado):
    if nombre not in medido:
        print("FALLA  --self-test conducta: el brazo '%s' no publico linea" % nombre)
        rc = 1
    elif medido[nombre] != esperado[nombre]:
        print("FALLA  --self-test conducta: el brazo '%s' publico otra linea" % nombre)
        print("  esperado: %s" % esperado[nombre])
        print("  medido:   %s" % medido[nombre])
        rc = 1
for nombre in sorted(set(medido) - set(esperado)):
    print("FALLA  --self-test conducta: el brazo '%s' publico linea sin base" % nombre)
    rc = 1
raise SystemExit(rc)
PY
}

# Coteja lo que el repo publica contra lo que el gate mide, en tres aserciones que no comparten
# lector: el bloque de resultados del README contra la corrida entera, la cifra de brazos que el
# comando documentado declara contra el censo, y las reglas que el README anuncia contra las que
# su contrato enumera. Las tres son la misma clase de defecto --una cifra publicada que nadie
# vuelve a comparar-- y ninguna se puede deducir de las otras dos: el bloque no dice cuantos
# brazos son, y el censo no dice cuantas reglas promete el contrato. Devuelve RC 1 si alguna
# falla y nombra la asercion y la linea, para que el rojo diga donde mirar y no solo que algo
# cambio. Es puro: recibe tres rutas y no invoca el gate, para que el decimo brazo lo falsue sin
# recursion. Fuera de alcance declarado: las menciones narrativas de brazos --«seis brazos se
# falsaban», «igual de cierta con siete brazos»--, que son historia fechada y obligarian a
# reescribir el pasado cada vez que nace un brazo, y los segundos del `--self-test`, que son una
# medida del host y no del sujeto.
cotejar_publicado() {
  python3 - "$1" "$2" "$3" <<'PY'
import re
import sys

NUM = {
    "uno": 1, "una": 1, "dos": 2, "tres": 3, "cuatro": 4, "cinco": 5, "seis": 6,
    "siete": 7, "ocho": 8, "nueve": 9, "diez": 10, "once": 11, "doce": 12,
    "trece": 13, "catorce": 14, "quince": 15, "diecinueve": 19,
}

readme, publicada, brazos = sys.argv[1], sys.argv[2], sys.argv[3]
with open(readme, encoding="utf-8") as f:
    lineas = f.read().splitlines()
with open(publicada, encoding="utf-8") as f:
    real = f.read().splitlines()
texto = "\n".join(lineas)
declarados = len(brazos.split())
rc = 0

# Primera: el bloque de resultados. Se ancla por su contenido --la linea del recuento de
# capsulas-- y no por su posicion, para que anadir un bloque de comandos arriba no la mueva.
vallas = [i for i, l in enumerate(lineas) if l.strip().startswith("```")]
bloque = None
for abre, cierra in zip(vallas, vallas[1:]):
    if any("capsulas: ataque RC 0" in l for l in lineas[abre + 1:cierra]):
        bloque = lineas[abre + 1:cierra]
        break
if bloque is None:
    print("FALLA  publicado: el README no publica bloque de resultados (ninguna valla contiene 'capsulas: ataque RC 0')")
    rc = 1
elif bloque != real:
    rc = 1
    print("FALLA  publicado: el bloque del README no es la corrida real (%d lineas publicadas, %d medidas)"
          % (len(bloque), len(real)))
    for i in range(max(len(bloque), len(real))):
        izq = bloque[i] if i < len(bloque) else "<sin linea>"
        der = real[i] if i < len(real) else "<sin linea>"
        if izq != der:
            print("  linea %d del bloque:" % (i + 1))
            print("    README:  %s" % izq)
            print("    corrida: %s" % der)
            break

# Segunda: cuantos brazos se falsan. El comando documentado lo afirma en prosa y el censo lo
# declara en `CENSO_BRAZOS`; si discrepan, uno de los dos miente. Mide apariciones, no
# afirmaciones: una cita literal del patron cuenta igual que una promesa, y por eso el README
# no lo reproduce en su prosa.
vivas = re.findall(r"de los (\w+) se falsan", texto)
if not vivas:
    print("FALLA  publicado: el README no declara cuantos brazos se falsan ('de los <n> se falsan')")
    rc = 1
for palabra in vivas:
    valor = NUM.get(palabra.lower())
    if valor is None:
        print("FALLA  publicado: la cifra de brazos '%s' no es un numero que este lector conozca" % palabra)
        rc = 1
    elif valor != declarados:
        print("FALLA  publicado: el README dice que se falsan '%s' (%d) y el censo declara %d"
              % (palabra, valor, declarados))
        rc = 1

# Tercera: cuantas reglas promete el contrato. La prosa las anuncia y la propia seccion las
# enumera; se cotejan las dos. Lo que esto no mide --que cada regla este implementada-- lo mide
# el brazo o la capsula que la ejerce, no un recuento.
try:
    ini = next(i for i, l in enumerate(lineas) if l.startswith("## Contrato de cada"))
except StopIteration:
    print("FALLA  publicado: el README no tiene la seccion '## Contrato de cada'")
    raise SystemExit(1)
fin = next((i for i in range(ini + 1, len(lineas)) if lineas[i].startswith("## ")), len(lineas))
enumeradas = sum(1 for l in lineas[ini + 1:fin] if re.match(r"^\d+\.\s+\*\*", l))
anunciadas = [(p, NUM[p.lower()]) for p in re.findall(r"(\w+) (?:reglas|promesas)", texto)
              if p.lower() in NUM]
if not anunciadas:
    print("FALLA  publicado: el README no anuncia cuantas reglas promete ('<n> reglas|promesas')")
    rc = 1
for palabra, valor in anunciadas:
    if valor != enumeradas:
        print("FALLA  publicado: el README anuncia '%s' (%d) y su contrato enumera %d reglas"
              % (palabra, valor, enumeradas))
        rc = 1

raise SystemExit(rc)
PY
}

# Coteja el certificado que el repo se firma a si mismo: una fila por brazo en
# `contrato.esperado` con el token que su linea verde tiene que publicar y el marcador que su
# FALLA tiene que imprimir. Medido el 17-Nov-2026 en una copia del arbol: sin este contrato,
# `--escribir-base` bendecia un brazo degradado a «OK --self-test: hecho» y la corrida salia
# RC 0 con «conducta de 10 brazos identica» --la base certificaba estabilidad, no fuerza--.
# Tres aserciones, cada una con su nombre: el registro y el censo son el mismo conjunto, el
# token verde esta en la linea publicada por ese brazo, y el marcador rojo lo imprime una FALLA
# del codigo. Devuelve RC 1 y nombra la fila. Es puro --recibe tres rutas y el censo y no invoca
# el gate-- para que el undecimo brazo lo falsifique sin recursion.
cotejar_contrato() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys

def lineas(ruta):
    with open(ruta, encoding="utf-8") as f:
        return f.read().splitlines()

registro, base, codigo = sys.argv[1], sys.argv[2], sys.argv[3]
censo = sys.argv[4].split()

filas = []
for n, linea in enumerate(lineas(registro), 1):
    if not linea.strip() or linea.lstrip().startswith("#"):
        continue
    campos = [c.strip() for c in linea.split("\t")]
    if len(campos) != 3 or not all(campos):
        print("FALLA  --self-test contrato: la fila %d del registro no tiene tres campos con valor" % n)
        raise SystemExit(1)
    filas.append(campos)

verdes = {brazo: verde for brazo, verde, _ in filas}
publicado = {}
for linea in lineas(base):
    if linea.strip():
        nombre, _, texto = linea.partition("|")
        publicado[nombre.strip()] = texto
rojos = "\n".join(l for l in lineas(codigo) if "FALLA" in l)

rc = 0
if len(verdes) != len(filas):
    print("FALLA  --self-test contrato: el registro repite un brazo; una fila por brazo")
    rc = 1
for nombre in sorted(set(censo) - set(verdes)):
    print("FALLA  --self-test contrato: el brazo '%s' no tiene fila en contrato.esperado" % nombre)
    rc = 1
for nombre in sorted(set(verdes) - set(censo)):
    print("FALLA  --self-test contrato: el registro declara '%s', que el censo no ejerce" % nombre)
    rc = 1
for brazo, verde, rojo in filas:
    if brazo not in publicado:
        print("FALLA  --self-test contrato: el brazo '%s' no publica linea que cotejar" % brazo)
        rc = 1
    elif verde not in publicado[brazo]:
        print("FALLA  --self-test contrato: la linea de '%s' ya no publica '%s'" % (brazo, verde))
        print("  linea: %s" % publicado[brazo])
        rc = 1
    if rojo not in rojos:
        print("FALLA  --self-test contrato: el marcador de '%s' no lo imprime el codigo: '%s'" % (brazo, rojo))
        rc = 1
raise SystemExit(rc)
PY
}

# La puerta de entrada. Hasta el 17-Nov-2026 el gate certificaba que lo bien formado explota y
# cierra, y nunca habia falsado que lo mal formado se rechace nombrando su causa: medido con tres
# directorios de sonda, ninguno de los tres defectos salia nombrado y los tres sumaban al censo.
# Publica el defecto y devuelve RC propio --0 admitida, 40 sin README, 41 campo duplicado, 42
# campo ausente, 43 sin PoC, 44 sin parche-- para que el noveno brazo pueda falsarlos sin correr
# el gate entero por cada uno.
admitir_capsula() {
  _cap=$1
  if [ ! -f "$_cap/README.md" ]; then
    echo "SIN_README: no existe ${_cap%/}/README.md, asi que no hay declaracion que leer"
    return 40
  fi
  for _campo in invariante falsador; do
    _n=$(grep -c "^$_campo:" "$_cap/README.md" 2>/dev/null)
    _n=${_n:-0}
    if [ "$_n" -eq 0 ]; then
      echo "SIN_DECLARACION: '$_campo:' no aparece en ${_cap%/}/README.md"
      return 42
    fi
    if [ "$_n" -gt 1 ]; then
      _valores=$(sed -n "s/^$_campo: *//p" "$_cap/README.md" | tr '\n' ' ')
      echo "CAMPO_DUPLICADO: '$_campo:' aparece $_n veces en ${_cap%/}/README.md (${_valores% }); solo la primera tendria lector"
      return 41
    fi
  done
  if [ ! -f "$_cap/exploit_poc.py" ]; then
    echo "SIN_POC: falta ${_cap%/}/exploit_poc.py, asi que no hay ataque que medir"
    return 43
  fi
  if [ ! -f "$_cap/patch_secure.py" ]; then
    echo "SIN_PARCHE: falta ${_cap%/}/patch_secure.py, asi que el RC 1 del parche no seria suyo"
    return 44
  fi
  return 0
}

# Cuenta sobre la poblacion admitida --la lista que escribe el bucle-- y no sobre un segundo
# glob del disco. Hasta el 17-Nov-2026 cada fraccion del censo releia `[0-9][0-9][0-9]-*/`, asi
# que dos lecturas del mismo arbol podian discrepar: medido, un directorio no admitido inflaba
# el denominador y uno con `invariante:` duplicado sumaba en dos columnas de la misma corrida.
contar_declaracion() {
  _lista=$1
  _patron=$2
  _n=0
  while IFS= read -r _c; do
    [ -n "$_c" ] || continue
    if grep -q "$_patron" "$_c/README.md" 2>/dev/null; then
      _n=$((_n + 1))
    fi
  done < "$_lista"
  printf '%s' "$_n"
}

# Sin esta prueba el cotejo seria otra marca sin lector: nadie sabria si sigue mirando. Se
# copia una capsula que hoy certifica, se le cambia `invariante:` por `retorno` --dejando
# `falsador: verifica`, que es la contradiccion-- y se exige RC distinto de 0 con la palabra
# PAREJA en la salida; despues se restaura la linea original y se exige RC 0. Dos
# direcciones: caza la mentira y no acusa a la capsula sana.
self_test() {
  origen=$(cd "$(dirname "$0")" && pwd) || return 1
  brazos_ok=""
  CONDUCTA_FICHERO=$(mktemp "${TMPDIR:-/tmp}/conducta.XXXXXX") || return 1
  trap 'rm -f "$CONDUCTA_FICHERO"' EXIT
  N_CENSO=$(printf '%s\n' $CENSO_BRAZOS | wc -w | tr -d ' ')
  capsula=$(cd "$origen" && ls -d [0-9][0-9][0-9]-*/ 2>/dev/null | while read -r c; do
    if grep -q '^falsador: verifica' "$c"README.md 2>/dev/null; then echo "$c"; break; fi
  done)
  if [ -z "$capsula" ]; then
    echo "FALLA  --self-test necesita al menos una capsula con 'falsador: verifica'"
    return 2
  fi

  jaula=$(mktemp -d "${TMPDIR:-/tmp}/pareja.XXXXXX") || return 1
  cp "$origen/verificar-capsulas.sh" "$origen/sujeto_roto.py" "$origen/parche_mentiroso.py" "$origen/inyector_reloj.py" "$jaula/" || return 1
  cp -R "$origen/${capsula%/}" "$jaula/" || return 1
  printf '| %s | prueba | A00:2021 |\n' "$(printf '%s' "$capsula" | cut -c1-3)" >"$jaula/README.md" || return 1
  cp "$jaula/$capsula"README.md "$jaula/declaracion.orig" || return 1

  sed 's/^invariante:.*/invariante: retorno/' "$jaula/declaracion.orig" >"$jaula/$capsula"README.md
  salida=$(cd "$jaula" && sh ./verificar-capsulas.sh 2>&1)
  rc_contradiccion=$?
  nombrada=$(printf '%s\n' "$salida" | grep -c 'PAREJA')

  cp "$jaula/declaracion.orig" "$jaula/$capsula"README.md
  (cd "$jaula" && sh ./verificar-capsulas.sh >/dev/null 2>&1)
  rc_coherente=$?
  rm -rf "$jaula"

  if [ "$rc_contradiccion" -eq 0 ] || [ "$nombrada" -eq 0 ]; then
    echo "FALLA  --self-test: la pareja contradictoria no se cazo (RC $rc_contradiccion, 'PAREJA' nombrada $nombrada veces)"
    return 1
  fi
  if [ "$rc_coherente" -ne 0 ]; then
    echo "FALLA  --self-test: la capsula con su declaracion original fue acusada (RC $rc_coherente)"
    return 1
  fi
  publicar_brazo pareja "OK     --self-test: 'invariante: retorno' con 'falsador: verifica' -> RC $rc_contradiccion nombrando PAREJA; la misma capsula con lo que declara hoy -> RC 0"
  brazos_ok="$brazos_ok pareja"

  # Segundo brazo, la frontera: una capsula que declara no tener libro y cuyo PoC escribe uno
  # tiene que salir roja nombrando FRONTERA; la misma capsula sin escribir, verde. Medido el
  # 17-Nov-2026: las cinco capsulas con `fuera-de-alcance` dejan cero residuo, asi que la
  # frontera era una promesa sin predicado. Aqui se le pone predicado y falsador propio.
  jaula=$(mktemp -d "${TMPDIR:-/tmp}/self-frontera.XXXXXX") || return 1
  cp "$origen/verificar-capsulas.sh" "$origen/sujeto_roto.py" "$origen/parche_mentiroso.py" "$origen/inyector_reloj.py" "$jaula/" || return 1
  mkdir "$jaula/999-frontera" || return 1
  printf '| 999 | prueba | A00:2021 |\n' >"$jaula/README.md" || return 1
  printf 'invariante: retorno\nfalsador: fuera-de-alcance\n' >"$jaula/999-frontera/README.md" || return 1
  : >"$jaula/999-frontera/patch_secure.py"
  cat >"$jaula/999-frontera/exploit_poc.py" <<'POC'
import pathlib, sys
args = sys.argv[1:]
if "--app" in args:
    app = args[args.index("--app") + 1]
    if "sujeto_roto" in app:
        sys.exit(3)
    sys.exit(0 if "--naive" in args else 1)
pathlib.Path("residuo.txt").write_text("x")
sys.exit(0)
POC
  salida=$(cd "$jaula" && sh ./verificar-capsulas.sh 2>&1)
  rc_residuo=$?
  nombrada=$(printf '%s\n' "$salida" | grep -c 'FRONTERA')

  cat >"$jaula/999-frontera/exploit_poc.py" <<'POC'
import sys
args = sys.argv[1:]
if "--app" in args:
    app = args[args.index("--app") + 1]
    if "sujeto_roto" in app:
        sys.exit(3)
    sys.exit(0 if "--naive" in args else 1)
sys.exit(0)
POC
  (cd "$jaula" && sh ./verificar-capsulas.sh >/dev/null 2>&1)
  rc_puro=$?
  rm -rf "$jaula"

  if [ "$rc_residuo" -eq 0 ] || [ "$nombrada" -eq 0 ]; then
    echo "FALLA  --self-test: el PoC que escribe no se cazo (RC $rc_residuo, 'FRONTERA' nombrada $nombrada veces)"
    return 1
  fi
  if [ "$rc_puro" -ne 0 ]; then
    echo "FALLA  --self-test: la capsula sin residuo fue acusada (RC $rc_puro)"
    return 1
  fi
  publicar_brazo frontera "OK     --self-test: PoC que escribe con 'falsador: fuera-de-alcance' -> RC $rc_residuo nombrando FRONTERA; el mismo PoC sin escribir -> RC 0"
  brazos_ok="$brazos_ok frontera"

  # Tercer brazo, el vocabulario: una etiqueta del censo que no se mide es prosa con formato
  # de dato. Se plantan las tres mentiras --mas una verdad del mismo tipo-- y se exige que
  # cada mentira salga roja nombrando su etiqueta y que la verdad no sea acusada.
  jaula=$(mktemp -d "${TMPDIR:-/tmp}/etiquetas.XXXXXX") || return 1
  cp "$origen/verificar-capsulas.sh" "$origen/sujeto_roto.py" "$origen/parche_mentiroso.py" "$origen/inyector_reloj.py" "$jaula/" || return 1
  : >"$jaula/README.md"
  # nombre : etiqueta : RC del PoC contra el parche mentiroso : fingidos que publica
  for fila in 996-x:roto:3:1 997-x:no-medido:0:3 998-x:roto:0:1 999-x:cuelga:0:1; do
    dir=${fila%%:*}
    resto=${fila#*:}
    etiqueta=${resto%%:*}
    resto=${resto#*:}
    rc_mentiroso=${resto%%:*}
    fingidos=${resto##*:}
    mkdir "$jaula/$dir" || return 1
    printf '| %s | prueba | A00:2021 |\n' "${dir%%-*}" >>"$jaula/README.md"
    printf 'invariante: estado\nfalsador: %s\n' "$etiqueta" >"$jaula/$dir/README.md"
    : >"$jaula/$dir/patch_secure.py"
    cat >"$jaula/$dir/exploit_poc.py" <<POC
import sys
args = sys.argv[1:]
if "--app" in args:
    app = args[args.index("--app") + 1]
    if "sujeto_roto" in app:
        sys.exit(3)
    if "mentiroso" in app:
        print("[FALSADOR] rechazos fingidos=$fingidos []")
        sys.exit($rc_mentiroso)
    sys.exit(0 if "--naive" in args else 1)
sys.exit(0)
POC
  done

  # Y el techo del eje: un tipo de oraculo que el instrumento no sabe leer --tiempo,
  # concurrencia-- no puede entrar por accidente. Si no tiene lector, se nombra TIPO y se
  # para; el hueco declarado es el que despues se convierte en acto.
  mkdir "$jaula/995-x" || return 1
  printf '| 995 | prueba | A00:2021 |\n' >>"$jaula/README.md"
  printf 'invariante: tiempo\nfalsador: verifica\n' >"$jaula/995-x/README.md"
  : >"$jaula/995-x/patch_secure.py"
  cat >"$jaula/995-x/exploit_poc.py" <<'POC'
import sys
args = sys.argv[1:]
if "--app" in args:
    app = args[args.index("--app") + 1]
    if "sujeto_roto" in app:
        sys.exit(3)
    sys.exit(0 if "--naive" in args or "mentiroso" in app else 1)
sys.exit(0)
POC

  salida=$(cd "$jaula" && sh ./verificar-capsulas.sh 2>&1)
  rc_etiquetas=$?
  n_nomedido=$(printf '%s\n' "$salida" | grep -c 'NO-MEDIDO')
  n_roto=$(printf '%s\n' "$salida" | grep -c 'ROTO:')
  n_cuelga=$(printf '%s\n' "$salida" | grep -c 'CUELGA:')
  n_tipo=$(printf '%s\n' "$salida" | grep -c 'TIPO:')
  acusada=$(printf '%s\n' "$salida" | grep -c 'FALLA  996-x/')

  printf '| 996 | prueba | A00:2021 |\n' >"$jaula/README.md"
  rm -rf "$jaula/995-x" "$jaula/997-x" "$jaula/998-x" "$jaula/999-x"
  (cd "$jaula" && sh ./verificar-capsulas.sh >/dev/null 2>&1)
  rc_verdad=$?
  rm -rf "$jaula"

  if [ "$rc_etiquetas" -eq 0 ] || [ "$n_nomedido" -eq 0 ] || [ "$n_roto" -eq 0 ] || [ "$n_cuelga" -eq 0 ] || [ "$n_tipo" -eq 0 ]; then
    echo "FALLA  --self-test: una etiqueta del censo paso sin lector (RC $rc_etiquetas; NO-MEDIDO $n_nomedido, ROTO $n_roto, CUELGA $n_cuelga, TIPO $n_tipo)"
    return 1
  fi
  if [ "$acusada" -ne 0 ] || [ "$rc_verdad" -ne 0 ]; then
    echo "FALLA  --self-test: el 'roto' que dice la verdad fue acusado (RC $rc_verdad, $acusada linea(s))"
    return 1
  fi
  publicar_brazo vocabulario "OK     --self-test: 'no-medido' con fingidos>0, 'roto' con RC 0, 'cuelga' que termina e 'invariante: tiempo' -> RC $rc_etiquetas nombrando NO-MEDIDO, ROTO, CUELGA y TIPO; el 'roto' verdadero -> RC 0"
  brazos_ok="$brazos_ok vocabulario"

  # Cuarto brazo, la dimension temporal: `reloj:` afirma que el sujeto pregunta la hora. Se
  # plantan dos capsulas --una que cambia de veredicto cuando el instante se mueve y otra que
  # lo ignora-- y se exige roja la segunda nombrando RELOJ y verde la primera. Sin este brazo
  # el campo seria otra marca sin lector: la undecima promesa sin falsador propio.
  jaula=$(mktemp -d "${TMPDIR:-/tmp}/reloj-self.XXXXXX") || return 1
  cp "$origen/verificar-capsulas.sh" "$origen/sujeto_roto.py" "$origen/parche_mentiroso.py" "$origen/inyector_reloj.py" "$jaula/" || return 1
  : >"$jaula/README.md"
  for fila in 993-x:sordo 994-x:sensible; do
    dir=${fila%%:*}
    clase=${fila##*:}
    mkdir "$jaula/$dir" || return 1
    printf '| %s | prueba | A00:2021 |\n' "${dir%%-*}" >>"$jaula/README.md"
    printf 'invariante: retorno\nfalsador: fuera-de-alcance\nreloj: AHORA\n' >"$jaula/$dir/README.md"
    : >"$jaula/$dir/patch_secure.py"
    if [ "$clase" = sensible ]; then
      desenlace='sys.exit(1 if os.environ.get("AHORA") else 0)'
    else
      desenlace='sys.exit(0)'
    fi
    cat >"$jaula/$dir/exploit_poc.py" <<POC
import os, sys
args = sys.argv[1:]
if "--app" in args:
    app = args[args.index("--app") + 1]
    if "sujeto_roto" in app:
        sys.exit(3)
    sys.exit(0 if "--naive" in args else 1)
$desenlace
POC
  done

  salida=$(cd "$jaula" && sh ./verificar-capsulas.sh 2>&1)
  rc_reloj=$?
  n_reloj=$(printf '%s\n' "$salida" | grep -c 'RELOJ')
  acusada=$(printf '%s\n' "$salida" | grep -c 'FALLA  994-x/')

  printf '| 994 | prueba | A00:2021 |\n' >"$jaula/README.md"
  rm -rf "$jaula/993-x"
  (cd "$jaula" && sh ./verificar-capsulas.sh >/dev/null 2>&1)
  rc_sensible=$?
  rm -rf "$jaula"

  if [ "$rc_reloj" -eq 0 ] || [ "$n_reloj" -eq 0 ]; then
    echo "FALLA  --self-test: el 'reloj:' que no mueve su veredicto no se cazo (RC $rc_reloj, 'RELOJ' nombrada $n_reloj veces)"
    return 1
  fi
  if [ "$acusada" -ne 0 ] || [ "$rc_sensible" -ne 0 ]; then
    echo "FALLA  --self-test: la capsula cuyo veredicto si cambia con el instante fue acusada (RC $rc_sensible, $acusada linea(s))"
    return 1
  fi
  publicar_brazo tiempo "OK     --self-test: 'reloj: AHORA' ignorado -> RC $rc_reloj nombrando RELOJ; el mismo campo con un veredicto que cambia -> RC 0"
  brazos_ok="$brazos_ok tiempo"

  # Quinto brazo, el alcance de la foto: la novena regla medía el residuo solo donde miraba, y
  # un PoC que escribia por `tempfile` o por `~` publicaba `0 con residuo` con la capsula en
  # verde --medido el 17-Nov-2026 en una jaula de sonda--. Se planta una capsula que escapa por
  # las dos rutas por defecto y se exige el rojo; despues la misma sin escribir, y se exige
  # verde. Sin el control negativo el brazo seria un siempre-rojo y no mediria nada.
  jaula=$(mktemp -d "${TMPDIR:-/tmp}/alcance.XXXXXX") || return 1
  cp "$origen/verificar-capsulas.sh" "$origen/sujeto_roto.py" "$origen/parche_mentiroso.py" "$origen/inyector_reloj.py" "$jaula/" || return 1
  printf '| 992 | prueba | A00:2021 |\n' >"$jaula/README.md" || return 1
  mkdir "$jaula/992-x" || return 1
  printf 'invariante: retorno\nfalsador: fuera-de-alcance\n' >"$jaula/992-x/README.md" || return 1
  : >"$jaula/992-x/patch_secure.py"
  cat >"$jaula/992-x/exploit_poc.py" <<'POC'
import os, pathlib, sys, tempfile
args = sys.argv[1:]
if "--app" in args:
    app = args[args.index("--app") + 1]
    if "sujeto_roto" in app:
        sys.exit(3)
    sys.exit(0 if "--naive" in args else 1)
with tempfile.NamedTemporaryFile("w", prefix="escapa-", suffix=".txt", delete=False) as f:
    f.write("x")
pathlib.Path(os.path.expanduser("~/.escapa")).write_text("x")
sys.exit(0)
POC

  salida=$(cd "$jaula" && sh ./verificar-capsulas.sh 2>&1)
  rc_alcance=$?
  n_frontera=$(printf '%s\n' "$salida" | grep -c 'FRONTERA')

  cat >"$jaula/992-x/exploit_poc.py" <<'POC'
import sys
args = sys.argv[1:]
if "--app" in args:
    app = args[args.index("--app") + 1]
    if "sujeto_roto" in app:
        sys.exit(3)
    sys.exit(0 if "--naive" in args else 1)
sys.exit(0)
POC
  (cd "$jaula" && sh ./verificar-capsulas.sh >/dev/null 2>&1)
  rc_callado=$?
  rm -rf "$jaula"

  if [ "$rc_alcance" -eq 0 ] || [ "$n_frontera" -eq 0 ]; then
    echo "FALLA  --self-test: el PoC que escapa por HOME/TMPDIR no se cazo (RC $rc_alcance, 'FRONTERA' nombrada $n_frontera veces)"
    return 1
  fi
  if [ "$rc_callado" -ne 0 ]; then
    echo "FALLA  --self-test: la capsula que no escribe fuera de su arbol fue acusada (RC $rc_callado)"
    return 1
  fi
  publicar_brazo alcance "OK     --self-test: PoC que escapa por 'tempfile' y '~' -> RC $rc_alcance nombrando FRONTERA; el mismo PoC sin escapar -> RC 0"
  brazos_ok="$brazos_ok alcance"

  # Sexto brazo, el entorno de las otras dos puertas: el quinto mide el alcance de la foto y
  # residuo_en_jaula pincha HOME/TMPDIR/XDG, pero con_limite y reloj_en_jaula heredaban los del
  # host --medido el 17-Nov-2026: tres puertas, un solo alcance--. Se mide por conducta y sin
  # tocar el HOME real: la trampa es el propio entorno heredado, que si las funciones no
  # pincharan seria su destino. El control positivo --el mismo PoC sin jaula, que si la
  # llena-- distingue el arreglo de una trampa sin lector.
  trampa=$(mktemp -d "${TMPDIR:-/tmp}/entorno.XXXXXX") || return 1
  mkdir "$trampa/capsula" || return 1
  cat >"$trampa/capsula/exploit_poc.py" <<'POC'
import os, tempfile
with open(os.path.expanduser("~/.escape-brazo"), "w") as f:
    f.write("x")
with tempfile.NamedTemporaryFile("w", prefix="escapa-", delete=False) as f:
    f.write("x")
print("[FALSADOR] rechazos fingidos=0 []")
POC
  pos=$(mktemp -d "${TMPDIR:-/tmp}/entorno-pos.XXXXXX") || return 1
  (cd "$trampa/capsula" && HOME="$pos" TMPDIR="$pos" python3 exploit_poc.py >/dev/null 2>&1)
  n_pos=$(find "$pos" -type f \( -name '.escape-brazo' -o -name 'escapa-*' \) | wc -l | tr -d ' ')
  neg=$(mktemp -d "${TMPDIR:-/tmp}/entorno-neg.XXXXXX") || return 1
  (
    export HOME="$neg" TMPDIR="$neg"
    con_limite "$trampa/capsula" ../parche_mentiroso.py "$LIMITE_FALSADOR" >/dev/null 2>&1
    reloj_en_jaula "$trampa/capsula" "$RELOJ_FUERA" "$LIMITE_FALSADOR" >/dev/null 2>&1
  )
  n_neg=$(find "$neg" -type f \( -name '.escape-brazo' -o -name 'escapa-*' \) | wc -l | tr -d ' ')
  rm -rf "$trampa" "$pos" "$neg"

  if [ "$n_pos" -lt 1 ]; then
    echo "FALLA  --self-test: el PoC de prueba no escribio ni sin jaula ($n_pos archivo(s)); el detector no mide"
    return 1
  fi
  if [ "$n_neg" -ne 0 ]; then
    echo "FALLA  --self-test: con_limite o reloj_en_jaula escribieron fuera de su casa ($n_neg archivo(s) en el entorno heredado)"
    return 1
  fi
  publicar_brazo entorno "OK     --self-test: 'tempfile' y '~' bajo con_limite y reloj_en_jaula -> 0 archivo(s) fuera de su casa; el mismo PoC sin jaula -> $n_pos"
  brazos_ok="$brazos_ok entorno"

  # Septimo brazo, el censo de los brazos: los seis anteriores se falsan a si mismos, pero
  # nadie medía cuantos eran. Medido el 17-Nov-2026: el numero seis vivia en el README y no en
  # un lector, asi que borrar el brazo del entorno dejaba la corrida en RC 0 con un brazo
  # menos. Aqui se falsa el cotejo en las dos direcciones: se le quita `entorno` a lo ejercido
  # y se exige que muerda nombrandolo; se le da el censo entero y se exige que calle.
  salida_censo=$(cotejar_censo "pareja frontera vocabulario tiempo alcance censo" "$CENSO_BRAZOS")
  rc_censo=$?
  nombrado_censo=$(printf '%s\n' "$salida_censo" | grep -c 'entorno')
  (cotejar_censo "$CENSO_BRAZOS" "$CENSO_BRAZOS" >/dev/null 2>&1)
  rc_censo_sano=$?

  if [ "$rc_censo" -eq 0 ] || [ "$nombrado_censo" -eq 0 ]; then
    echo "FALLA  --self-test: el censo no mordio al brazo ausente (RC $rc_censo, 'entorno' nombrado $nombrado_censo veces)"
    return 1
  fi
  if [ "$rc_censo_sano" -ne 0 ]; then
    echo "FALLA  --self-test: el censo acuso al conjunto completo (RC $rc_censo_sano)"
    return 1
  fi
  publicar_brazo censo "OK     --self-test: censo de $N_CENSO brazos cotejado por nombre; sin 'entorno' -> RC $rc_censo nombrandolo; con el censo entero -> RC 0"
  brazos_ok="$brazos_ok censo"

  # Octavo brazo, la conducta de los brazos: el septimo coteja nombres, y un brazo vaciado por
  # dentro conserva el suyo. Aqui se falsa `cotejar_conducta` en las dos direcciones con bases
  # sinteticas --una con la linea del brazo `sonda`, otra vacia--: se exige que muerda
  # nombrandola y que calle ante la base entera. Las bases son sinteticas a proposito: el brazo
  # mide que el lector muerde, y la base real la coteja el cierre incondicional de mas abajo.
  base_sana=$(mktemp "${TMPDIR:-/tmp}/base.XXXXXX") || return 1
  base_mutilada=$(mktemp "${TMPDIR:-/tmp}/base.XXXXXX") || return 1
  printf 'sonda|linea medida\n' > "$base_sana"
  : > "$base_mutilada"
  salida_conducta=$(cotejar_conducta "$base_mutilada" "$base_sana")
  rc_conducta=$?
  nombrado_conducta=$(printf '%s\n' "$salida_conducta" | grep -c "brazo 'sonda'")
  (cotejar_conducta "$base_sana" "$base_sana" >/dev/null 2>&1)
  rc_conducta_sano=$?
  rm -f "$base_sana" "$base_mutilada"

  if [ "$rc_conducta" -eq 0 ] || [ "$nombrado_conducta" -eq 0 ]; then
    echo "FALLA  --self-test: la conducta no mordio a la base sin la linea de 'sonda' (RC $rc_conducta, nombrado $nombrado_conducta veces)"
    return 1
  fi
  if [ "$rc_conducta_sano" -ne 0 ]; then
    echo "FALLA  --self-test: la conducta acuso a la base entera (RC $rc_conducta_sano)"
    return 1
  fi
  publicar_brazo conducta "OK     --self-test: conducta cotejada contra la base; sin la linea de un brazo -> RC $rc_conducta nombrandolo; con la base entera -> RC 0"
  brazos_ok="$brazos_ok conducta"

  # Noveno brazo, la admision: las ocho anteriores miden el alcance de un lector sobre lo ya
  # admitido, y ninguna media que se admitio. Se falsa en las dos direcciones --tres defectos
  # tienen que salir nombrados, y una pareja de una sana mas una rechazada tiene que certificar
  # la sana sin que la rechazada infle ni reste el denominador-- porque una admision que mueva la
  # cifra pareceria segura. Limite medido el 17-Nov-2026: la mutacion que rechaza TODA capsula no
  # la muerde este brazo --sin admitidas no hay poblacion que medir--, la muerde el primero, que
  # publica que la pareja no se cazo. Lo que este brazo falsa es la direccion que los otros pueden
  # dejar pasar: el rechazo que se cuela en el denominador.
  jaula=$(mktemp -d "${TMPDIR:-/tmp}/admision.XXXXXX") || return 1
  cp "$origen/verificar-capsulas.sh" "$origen/sujeto_roto.py" "$origen/parche_mentiroso.py" "$origen/inyector_reloj.py" "$jaula/" || return 1
  printf '| 901 | prueba | A00:2021 |\n| 902 | prueba | A00:2021 |\n| 903 | prueba | A00:2021 |\n' >"$jaula/README.md" || return 1
  mkdir "$jaula/901-x" "$jaula/902-x" "$jaula/903-x" || return 1
  cat >"$jaula/901-x/exploit_poc.py" <<'POC'
import sys
sys.exit(0)
POC
  cp "$jaula/901-x/exploit_poc.py" "$jaula/902-x/exploit_poc.py"
  : >"$jaula/901-x/patch_secure.py"
  : >"$jaula/902-x/patch_secure.py"
  : >"$jaula/903-x/patch_secure.py"
  # El campo duplicado no es redundancia: declara `estado` y `retorno` a la vez, y `verifica`
  # contradice al segundo. Con `head -1` esa capsula salia OK con la contradiccion dentro.
  printf 'invariante: estado\ninvariante: retorno\nfalsador: verifica\n' >"$jaula/902-x/README.md" || return 1
  printf 'invariante: estado\nfalsador: verifica\n' >"$jaula/903-x/README.md" || return 1

  salida=$(cd "$jaula" && sh ./verificar-capsulas.sh 2>&1)
  rc_admision=$?
  n_sin_readme=$(printf '%s\n' "$salida" | grep -c 'SIN_README')
  n_duplicado=$(printf '%s\n' "$salida" | grep -c 'CAMPO_DUPLICADO')
  n_sin_poc=$(printf '%s\n' "$salida" | grep -c 'SIN_POC')
  n_rechazadas=$(printf '%s\n' "$salida" | grep -c 'no admitidos: no cuentan en el denominador')
  rm -rf "$jaula"

  # Y la direccion que impide el siempre-rojo: una sana junto a una rechazada. La tabla anuncia
  # solo la sana, que es lo que la poblacion admite.
  jaula=$(mktemp -d "${TMPDIR:-/tmp}/admision-pob.XXXXXX") || return 1
  cp "$origen/verificar-capsulas.sh" "$origen/sujeto_roto.py" "$origen/parche_mentiroso.py" "$origen/inyector_reloj.py" "$jaula/" || return 1
  printf '| 904 | prueba | A00:2021 |\n' >"$jaula/README.md" || return 1
  mkdir "$jaula/901-x" "$jaula/904-x" || return 1
  : >"$jaula/901-x/patch_secure.py"
  printf 'invariante: estado\nfalsador: verifica\n' >"$jaula/904-x/README.md" || return 1
  : >"$jaula/904-x/patch_secure.py"
  cat >"$jaula/904-x/exploit_poc.py" <<'POC'
import sys
args = sys.argv[1:]
if "--app" in args:
    app = args[args.index("--app") + 1]
    if "sujeto_roto" in app:
        sys.exit(3)
    if "mentiroso" in app:
        print("[FALSADOR] rechazos fingidos=0 []")
        sys.exit(0)
    sys.exit(0 if "--naive" in args else 1)
sys.exit(0)
POC
  salida_pob=$(cd "$jaula" && sh ./verificar-capsulas.sh 2>&1)
  rc_poblacion=$?
  n_sana=$(printf '%s\n' "$salida_pob" | grep -c '^OK     904-x/')
  n_denominador=$(printf '%s\n' "$salida_pob" | grep -c '^1/1 capsulas:')
  rm -rf "$jaula"

  if [ "$rc_admision" -eq 0 ] || [ "$n_sin_readme" -eq 0 ] || [ "$n_duplicado" -eq 0 ] || [ "$n_sin_poc" -eq 0 ] || [ "$n_rechazadas" -eq 0 ]; then
    echo "FALLA  --self-test: la admision no cazo o no nombro (RC $rc_admision; SIN_README $n_sin_readme, CAMPO_DUPLICADO $n_duplicado, SIN_POC $n_sin_poc, rechazadas $n_rechazadas)"
    return 1
  fi
  # RC 1 aqui es el acierto: la rechazada tiene que sonar. Lo que se exige del denominador es que
  # la sana aparezca certificada y que el rechazado no la infle ni la reste.
  if [ "$rc_poblacion" -ne 1 ] || [ "$n_sana" -eq 0 ] || [ "$n_denominador" -eq 0 ]; then
    echo "FALLA  --self-test: la pareja sana+rechazada no midio la poblacion (RC $rc_poblacion, '904' certificada $n_sana, '1/1' $n_denominador)"
    return 1
  fi
  publicar_brazo admision "OK     --self-test: sin README, 'invariante:' duplicado y sin PoC -> RC $rc_admision nombrando SIN_README, CAMPO_DUPLICADO y SIN_POC; una sana junto a una rechazada -> RC $rc_poblacion con '1/1' en el denominador"
  brazos_ok="$brazos_ok admision"

  # Decimo brazo, lo publicado: las nueve anteriores miden lo que el gate comprueba, y ninguna
  # media lo que el repo anuncia. Medido el 17-Nov-2026: el bloque de resultados del README se
  # habia cotejado a mano una vez y ningun lector lo comparaba en cada push, asi que editar una
  # fraccion del script sin tocar el bloque dejaba el CI en verde con el escaparate publicando
  # una cifra que ya no media. El sujeto de ese cotejo es la corrida entera --no un resumen de
  # ella--, y por eso se corre el gate sobre el arbol real en vez de copiarlo: una copia del
  # arbol mide la copia. Coste medido ese dia: 18,4 s de corrida completa, que es lo que cuesta
  # que la cifra publicada tenga lector.
  #
  # Se falsa en las cuatro direcciones que el lector tiene --el README real tiene que callar, y
  # cada una de las tres aserciones mutilada por separado tiene que ser nombrada--, porque una
  # asercion sin falsador es exactamente la promesa que este brazo existe para no publicar.
  # Fuera de alcance declarado: las menciones narrativas de brazos («Seis brazos se falsaban»,
  # «igual de cierta con siete brazos») y los segundos del `--self-test`. Son historia fechada y
  # una medida del host; cotejarlas obligaria a reescribir el pasado cada vez que nace un brazo.
  #
  # Y una mordida propia, el mismo 17-Nov-2026: el primer borrador llamo `n_brazos` a su cuenta
  # de lineas nombradas y piso la variable que el cierre publica, con lo que el gate salio verde
  # anunciando «1 brazos ejercidos» sobre un censo de 10. La cifra no tenia lector; ahora se
  # llama `N_CENSO` y ningun brazo la toca.
  publicada=$(mktemp "${TMPDIR:-/tmp}/publicada.XXXXXX") || return 1
  copia_readme=$(mktemp "${TMPDIR:-/tmp}/readme.XXXXXX") || return 1
  trap 'rm -f "$CONDUCTA_FICHERO" "${publicada:-}" "${copia_readme:-}"' EXIT

  (cd "$origen" && sh ./verificar-capsulas.sh >"$publicada" 2>&1)
  rc_corrida_publicada=$?
  if [ "$rc_corrida_publicada" -ne 0 ]; then
    echo "FALLA  --self-test: la corrida real no sale en verde (RC $rc_corrida_publicada) y el bloque no se puede cotejar"
    return 1
  fi

  cp "$origen/README.md" "$copia_readme" || return 1
  salida_sana=$(cotejar_publicado "$copia_readme" "$publicada" "$CENSO_BRAZOS")
  rc_sano=$?
  nom_sano=$(printf '%s\n' "$salida_sana" | grep -c '^FALLA')

  python3 -c 'import re,sys
t=open(sys.argv[1],encoding="utf-8").read()
open(sys.argv[2],"w",encoding="utf-8").write(re.sub(r"(?m)^(\d+/\d+ capsulas:)",lambda m:"1"+m.group(1),t,count=1))' "$origen/README.md" "$copia_readme" || return 1
  salida_bloque=$(cotejar_publicado "$copia_readme" "$publicada" "$CENSO_BRAZOS")
  rc_bloque=$?
  nom_bloque=$(printf '%s\n' "$salida_bloque" | grep -c 'el bloque del README no es la corrida real')

  python3 -c 'import re,sys
t=open(sys.argv[1],encoding="utf-8").read()
open(sys.argv[2],"w",encoding="utf-8").write(re.sub(r"(de los )\w+( se falsan)",r"\1diecinueve\2",t,count=1))' "$origen/README.md" "$copia_readme" || return 1
  salida_brazos=$(cotejar_publicado "$copia_readme" "$publicada" "$CENSO_BRAZOS")
  rc_brazos=$?
  nom_brazos=$(printf '%s\n' "$salida_brazos" | grep -c 'y el censo declara')

  python3 -c 'import re,sys
t=open(sys.argv[1],encoding="utf-8").read()
open(sys.argv[2],"w",encoding="utf-8").write(re.sub(r"(\w+)( (?:reglas|promesas))",r"quince\2",t,count=1))' "$origen/README.md" "$copia_readme" || return 1
  salida_reglas=$(cotejar_publicado "$copia_readme" "$publicada" "$CENSO_BRAZOS")
  rc_reglas=$?
  nom_reglas=$(printf '%s\n' "$salida_reglas" | grep -c 'y su contrato enumera')
  rm -f "$publicada" "$copia_readme"

  # El control positivo va primero: un lector que acusa al README correcto no mide nada, y sus
  # tres rojos de abajo serian indistinguibles de un lector roto.
  if [ "$rc_sano" -ne 0 ] || [ "$nom_sano" -ne 0 ]; then
    echo "FALLA  --self-test: lo publicado acuso al README real (RC $rc_sano, $nom_sano lineas FALLA)"
    printf '%s\n' "$salida_sana" | sed 's/^/       /'
    return 1
  fi
  if [ "$rc_bloque" -eq 0 ] || [ "$nom_bloque" -eq 0 ]; then
    echo "FALLA  --self-test: lo publicado no mordio el bloque mutilado (RC $rc_bloque, nombrado $nom_bloque veces)"
    return 1
  fi
  if [ "$rc_brazos" -eq 0 ] || [ "$nom_brazos" -eq 0 ]; then
    echo "FALLA  --self-test: lo publicado no mordio la cifra de brazos mutilada (RC $rc_brazos, nombrada $nom_brazos veces)"
    return 1
  fi
  if [ "$rc_reglas" -eq 0 ] || [ "$nom_reglas" -eq 0 ]; then
    echo "FALLA  --self-test: lo publicado no mordio el recuento del contrato mutilado (RC $rc_reglas, nombrado $nom_reglas veces)"
    return 1
  fi
  publicar_brazo publicado "OK     --self-test: bloque, censo en prosa y contrato cotejados contra la corrida real; cada asercion mutilada -> RC $rc_bloque/$rc_brazos/$rc_reglas nombrandola; el README real -> RC $rc_sano"
  brazos_ok="$brazos_ok publicado"

  # Undecimo brazo: el contrato de la base. Corre despues del decimo y antes del cotejo final
  # porque mide el certificado que los otros diez firman, y aqui se falsifica en cuatro
  # direcciones: registro al que le falta un brazo, linea publicada que pierde su token verde,
  # marcador rojo que el codigo no imprime, y el registro real como control positivo --primero,
  # porque un lector que acusa al registro correcto no mide nada y sus tres rojos serian
  # indistinguibles de un lector roto--.
  jaula_contrato=$(mktemp -d "${TMPDIR:-/tmp}/contrato.XXXXXX") || return 1
  trap 'rm -f "$CONDUCTA_FICHERO"; rm -rf "${jaula_contrato:-}"' EXIT
  python3 - "$origen/contrato.esperado" "$origen/brazos.esperado" "$jaula_contrato" <<'PY' || return 1
import sys

registro, base, destino = sys.argv[1], sys.argv[2], sys.argv[3]
reg = open(registro, encoding="utf-8").read().splitlines()
bas = open(base, encoding="utf-8").read().splitlines()

def escribir(nombre, lineas):
    with open("%s/%s" % (destino, nombre), "w", encoding="utf-8") as f:
        f.write("\n".join(lineas) + "\n")

escribir("sin-fila", [l for l in reg if not l.startswith("tiempo\t")])
escribir("sin-token", [l.replace("PAREJA", "el marcador") if l.startswith("pareja|") else l for l in bas])
escribir("rojo-falso", ["\t".join(l.split("\t")[:2] + ["MARCADOR-QUE-EL-CODIGO-NO-IMPRIME"])
                        if l.startswith("pareja\t") else l for l in reg])
PY
  codigo_contrato="$origen/verificar-capsulas.sh"
  salida_cfila=$(cotejar_contrato "$jaula_contrato/sin-fila" "$origen/brazos.esperado" "$codigo_contrato" "$CENSO_BRAZOS")
  rc_cfila=$?
  nom_cfila=$(printf '%s\n' "$salida_cfila" | grep -c "no tiene fila en contrato.esperado")
  salida_ctoken=$(cotejar_contrato "$origen/contrato.esperado" "$jaula_contrato/sin-token" "$codigo_contrato" "$CENSO_BRAZOS")
  rc_ctoken=$?
  nom_ctoken=$(printf '%s\n' "$salida_ctoken" | grep -c "ya no publica")
  salida_crojo=$(cotejar_contrato "$jaula_contrato/rojo-falso" "$origen/brazos.esperado" "$codigo_contrato" "$CENSO_BRAZOS")
  rc_crojo=$?
  nom_crojo=$(printf '%s\n' "$salida_crojo" | grep -c "no lo imprime el codigo")
  rm -rf "$jaula_contrato"

  if [ "$rc_cfila" -eq 0 ] || [ "$nom_cfila" -eq 0 ]; then
    echo "FALLA  --self-test: el contrato no cazo al brazo sin fila (RC $rc_cfila, nombrado $nom_cfila veces)"
    return 1
  fi
  if [ "$rc_ctoken" -eq 0 ] || [ "$nom_ctoken" -eq 0 ]; then
    echo "FALLA  --self-test: el contrato no cazo la linea sin su token verde (RC $rc_ctoken, nombrado $nom_ctoken veces)"
    return 1
  fi
  if [ "$rc_crojo" -eq 0 ] || [ "$nom_crojo" -eq 0 ]; then
    echo "FALLA  --self-test: el contrato no cazo el marcador que el codigo no imprime (RC $rc_crojo, nombrado $nom_crojo veces)"
    return 1
  fi
  publicar_brazo contrato "OK     --self-test: registro y censo con $N_CENSO filas cotejados; sin una fila -> RC $rc_cfila nombrandolo, la linea que pierde su token verde -> RC $rc_ctoken, el marcador que el codigo no imprime -> RC $rc_crojo"
  brazos_ok="$brazos_ok contrato"

  # El control positivo va despues de publicar: el registro describe tambien la linea de este
  # brazo, y esa linea no existe hasta que el brazo la publica. Se coteja contra la conducta
  # viva --un registro que acusa a lo que los brazos acaban de decir no mide nada--; contra la
  # base en vigor lo coteja el cierre, que es otro sujeto: el certificado, no la conducta.
  salida_csano=$(cotejar_contrato "$origen/contrato.esperado" "$CONDUCTA_FICHERO" "$codigo_contrato" "$CENSO_BRAZOS")
  rc_csano=$?
  nom_csano=$(printf '%s\n' "$salida_csano" | grep -c 'FALLA')
  if [ "$rc_csano" -ne 0 ] || [ "$nom_csano" -ne 0 ]; then
    echo "FALLA  --self-test: el contrato acuso a la conducta real (RC $rc_csano, $nom_csano lineas FALLA)"
    printf '%s\n' "$salida_csano" | sed 's/^/       /'
    return 1
  fi

  # Cotejo final, incondicional y fuera del septimo y del octavo brazo: si un brazo desaparece
  # del codigo no ejecuta su propio apunte, y el silencio es su unica huella. Puesto aqui,
  # borrar el septimo tampoco borra su lector --el cotejo sigue viendo que falta `censo`--, y
  # borrar el octavo tampoco borra el cotejo de conducta.
  salida_final=$(cotejar_censo "$brazos_ok" "$CENSO_BRAZOS")
  rc_final=$?
  if [ "$rc_final" -ne 0 ]; then
    printf '%s\n' "$salida_final"
    return 1
  fi
  echo "OK     --self-test: $N_CENSO brazos ejercidos, todos declarados en el censo"

  base_brazos="$origen/brazos.esperado"
  if [ "${REESCRIBIR_BASE:-0}" = 1 ]; then
    cp "$CONDUCTA_FICHERO" "$base_brazos" || return 1
    echo "BASE   --self-test: brazos.esperado reescrito con $(wc -l < "$base_brazos" | tr -d ' ') lineas"
  else
    if [ ! -f "$base_brazos" ]; then
      echo "FALLA  --self-test: falta la base de conducta brazos.esperado; creala con --escribir-base"
      return 2
    fi
    salida_final_conducta=$(cotejar_conducta "$CONDUCTA_FICHERO" "$base_brazos")
    rc_final_conducta=$?
    if [ "$rc_final_conducta" -ne 0 ]; then
      printf '%s\n' "$salida_final_conducta"
      echo "PISTA  --self-test: si el cambio de conducta es deliberado, reescribe la base con --escribir-base"
      return 1
    fi
    echo "OK     --self-test: conducta de $N_CENSO brazos identica a brazos.esperado"
  fi

  # El contrato se aplica a la base en vigor --tambien a la que acaba de escribir
  # `--escribir-base`-- y vive fuera de todo brazo: un brazo borrado no puede llevarse su lector.
  # Es la puerta que cierra la auto-bendicion: el unico escritor de la base ya no puede bendecir
  # una linea que pierda el token de lo que el brazo mide.
  if [ ! -f "$origen/contrato.esperado" ]; then
    echo "FALLA  --self-test: falta el registro de contrato contrato.esperado"
    return 2
  fi
  salida_final_contrato=$(cotejar_contrato "$origen/contrato.esperado" "$base_brazos" "$origen/verificar-capsulas.sh" "$CENSO_BRAZOS")
  rc_final_contrato=$?
  if [ "$rc_final_contrato" -ne 0 ]; then
    printf '%s\n' "$salida_final_contrato"
    echo "PISTA  --self-test: si un brazo cambio lo que mide, actualiza su fila en contrato.esperado en el mismo acto"
    return 1
  fi
  echo "OK     --self-test: contrato de los $N_CENSO brazos cotejado contra contrato.esperado y contra el codigo"
  return 0
}

case "${1:-}" in
  --self-test) self_test; exit $? ;;
  --escribir-base) REESCRIBIR_BASE=1; self_test; exit $? ;;
  "") ;;
  *) echo "uso: $0 [--self-test | --escribir-base]"; exit 20 ;;
esac

fallos=0
total=0
fronteras=0
con_residuo=0
medidas=0
relojes=0
caducan=0
rechazadas=0

# La poblacion se escribe una sola vez: es la lista de capsulas admitidas y la unica fuente de
# los denominadores del censo. Antes cada fraccion releia `[0-9][0-9][0-9]-*/` por su cuenta, y
# dos lecturas del mismo arbol pueden discrepar --medido el 17-Nov-2026: una capsula con
# `invariante:` duplicado sumaba a la vez en `estado` y en `retorno` de la misma corrida--.
POBLACION_FICHERO=$(mktemp "${TMPDIR:-/tmp}/poblacion.XXXXXX") || exit 1
trap 'rm -f "$POBLACION_FICHERO"' EXIT

for capsula in [0-9][0-9][0-9]-*/; do
  [ -d "$capsula" ] || continue

  # La admision va antes de contar. Medido el 17-Nov-2026 con tres directorios de sonda: sin
  # README salia nombrado con dos causas que no eran la suya, con `invariante:` dos veces salia
  # OK llevando la contradiccion dentro, y sin `exploit_poc.py` se acusaba de «creerse el rechazo
  # declarado». Los tres sumaban al censo publicando salud sobre lo que no era una capsula.
  # `fallos` cuenta capsulas ADMITIDAS que no cumplen; `rechazadas`, directorios que no son
  # capsulas. Sumar la rechazada a `fallos` publicaba `0/1` con la unica admitida en verde, la
  # primera fraccion restando de un total donde el rechazado no entraba --medido el 17-Nov-2026
  # por el noveno brazo, que por eso exige ver la sana certificada--.
  if ! motivo_admision=$(admitir_capsula "$capsula"); then
    echo "FALLA  ${capsula%/} ADMISION: $motivo_admision"
    rechazadas=$((rechazadas + 1))
    continue
  fi

  printf '%s\n' "${capsula%/}" >>"$POBLACION_FICHERO"
  total=$((total + 1))

  # Las dos lineas se leen, y la frontera se mide, sobre el estado PRISTINO: antes de que esta
  # corrida toque la capsula. Medida despues, la foto «antes» ya incluiria lo que el propio PoC
  # acaba de escribir en el arbol de trabajo y el residuo seria invisible --el falso verde que
  # esta regla existe para cazar, cometido por la regla misma--.
  invariante=$(sed -n 's/^invariante: *//p' "$capsula"README.md 2>/dev/null | head -1)
  falsador_declarado=$(sed -n 's/^falsador: *//p' "$capsula"README.md 2>/dev/null | head -1)
  reloj_declarado=$(sed -n 's/^reloj: *//p' "$capsula"README.md 2>/dev/null | head -1)
  escrito=-1
  if [ "$falsador_declarado" = fuera-de-alcance ]; then
    escrito=$(residuo_en_jaula "$capsula")
  fi

  (cd "$capsula" && python3 exploit_poc.py >/dev/null 2>&1)
  vulnerable=$?

  (cd "$capsula" && python3 exploit_poc.py --app patch_secure.py >/dev/null 2>&1)
  parche=$?

  # El parche ingenuo cierra el caso reportado y deja abierta la clase de fallo:
  # si acaso lo cerrara, el README estaria vendiendo una refutacion que no existe.
  (cd "$capsula" && python3 exploit_poc.py --app patch_secure.py --naive >/dev/null 2>&1)
  ingenuo=$?

  # El tercer modo impide el falso verde: un sujeto que falla siempre no puede
  # ser absuelto con 1.
  (cd "$capsula" && python3 exploit_poc.py --app ../sujeto_roto.py >/dev/null 2>&1)
  roto=$?

  # Cuarto modo, por capsula: los controles que la propia capsula declara. Cada
  # `control_*.py` es una promesa escrita en su README --«un error interno no es un
  # cupon cerrado», «una deduccion no es una apertura»-- y aqui tiene su lector. Si
  # alguno devolviera 1, la promesa seria prosa.
  controles=$roto
  hay_control=no
  for control in "$capsula"control_*.py; do
    [ -f "$control" ] || continue
    hay_control=si
    (cd "$capsula" && python3 exploit_poc.py --app "../$control" >/dev/null 2>&1)
    rc=$?
    [ "$rc" -eq 3 ] || controles=$rc
  done
  [ "$hay_control" = si ] || controles=3

  # Quinto modo, declarado por capsula: si el README dice `falsador: verifica`, el PoC
  # afirma que no se cree un rechazo declarado --que mira el libro despues de la
  # excepcion-- y aqui tiene su lector. Un RC 0 significa que detecto el efecto pese al
  # rechazo; un RC 1 significa que se lo creyo. Los otros cuatro valores del censo tienen
  # lector propio desde el 17-Nov-2026: hasta entonces pasaban por un `;;` vacio y el censo
  # los imprimia como datos.
  # (las declaraciones ya se leyeron sobre el estado pristino, con la frontera medida)
  censo_ok=si
  pareja_conocida=si
  censo="$falsador_declarado"
  case "$invariante" in
    estado|retorno) ;;
    *) echo "FALLA  $capsula TIPO: 'invariante: $invariante' no tiene lector; los tipos que lo tienen son estado y retorno"; censo_ok=no; pareja_conocida=no ;;
  esac
  case "$falsador_declarado" in
    verifica)
      (cd "$capsula" && python3 exploit_poc.py --app ../parche_mentiroso.py >/dev/null 2>&1)
      rc_falsador=$?
      if [ "$rc_falsador" -ne 0 ]; then
        if [ "$rc_falsador" -eq 4 ]; then
          echo "FALLA  $capsula falsador: RC 4, una via se cree el rechazo aunque su vecina lo vea"
        else
          echo "FALLA  $capsula falsador: RC $rc_falsador, el PoC se cree el rechazo declarado"
        fi
        censo_ok=no
      else
        medidas=$((medidas + 1))
      fi
      ;;
    fuera-de-alcance)
      # Coste medido el 17-Nov-2026: +2,1 s sobre 18,9 s de gate.
      fronteras=$((fronteras + 1))
      if [ "$escrito" -ne 0 ]; then
        echo "FALLA  $capsula FRONTERA: declara que no hay libro que mirar y su PoC escribio dentro de la jaula ($escrito linea(s) de diferencia en su arbol, HOME, TMPDIR o XDG)"
        censo_ok=no
        con_residuo=$((con_residuo + 1))
      else
        censo="fuera-de-alcance+medido"
        medidas=$((medidas + 1))
      fi
      ;;
    no-medido)
      # La etiqueta afirma que el testigo no declaro ningun rechazo que falsificar. Eso lo
      # dice el propio falsificador en su contador: cero fingidos es la unica forma de que
      # su RC 0 no signifique «se creyo la mentira».
      medida=$(con_limite "$capsula" ../parche_mentiroso.py "$LIMITE_FALSADOR")
      rc_medido=$(printf '%s' "$medida" | sed -n 's/^RC=\([0-9]*\).*/\1/p')
      fingidos=$(printf '%s' "$medida" | sed -n 's/.*FINGIDOS=\([0-9]*\).*/\1/p')
      if [ "$rc_medido" = 0 ] && [ "$fingidos" = 0 ]; then
        censo="no-medido+medido"
        medidas=$((medidas + 1))
      else
        echo "FALLA  $capsula NO-MEDIDO: declara cero rechazos fingidos y el falsificador conto ${fingidos:-?} con RC ${rc_medido:-?}"
        censo_ok=no
      fi
      ;;
    roto)
      # La etiqueta afirma que el falsificador rompe el sujeto: eso es un RC 3 o no es nada.
      medida=$(con_limite "$capsula" ../parche_mentiroso.py "$LIMITE_FALSADOR")
      rc_medido=$(printf '%s' "$medida" | sed -n 's/^RC=\([0-9]*\).*/\1/p')
      if [ "$rc_medido" = 3 ]; then
        censo="roto+medido"
        medidas=$((medidas + 1))
      else
        echo "FALLA  $capsula ROTO: declara que el falsificador rompe el sujeto y dio RC ${rc_medido:-?}"
        censo_ok=no
      fi
      ;;
    cuelga)
      # Colgarse no deja codigo de salida: la unica medida es el reloj. Se declara el limite
      # porque «cuelga» sin numero es una promesa que no se puede refutar.
      medida=$(con_limite "$capsula" ../parche_mentiroso.py "$LIMITE_CUELGA")
      rc_medido=$(printf '%s' "$medida" | sed -n 's/^RC=\([0-9]*\).*/\1/p')
      if [ "$rc_medido" = 124 ]; then
        censo="cuelga+medido"
        medidas=$((medidas + 1))
      else
        echo "FALLA  $capsula CUELGA: declara no terminar en ${LIMITE_CUELGA}s y termino con RC ${rc_medido:-?}"
        censo_ok=no
      fi
      ;;
    *) echo "FALLA  $capsula falsador: valor no reconocido '$falsador_declarado'"; censo_ok=no; pareja_conocida=no ;;
  esac

  # La dimension temporal, en campo aparte porque no es un tipo de oraculo: `reloj: <VAR>`
  # afirma que el sujeto pregunta la hora. Se mueve el instante a RELOJ_FUERA con el inyector
  # y se exige que el veredicto cambie. Si no cambia, el campo decoraba; si el sujeto se cuelga
  # al moverlo, un juicio y un cuelgue no se distinguen y se publica como falla.
  if [ -n "$reloj_declarado" ]; then
    case "$reloj_declarado" in
      *[!A-Z0-9_]*|[0-9]*)
        echo "FALLA  $capsula RELOJ: 'reloj: $reloj_declarado' no es un nombre de variable"
        censo_ok=no
        ;;
      *)
        relojes=$((relojes + 1))
        rc_fuera=$(reloj_en_jaula "$capsula" "$RELOJ_FUERA" "$LIMITE_FALSADOR" | sed -n 's/^RC=\([0-9]*\).*/\1/p')
        if [ -z "$rc_fuera" ] || [ "$rc_fuera" -eq 99 ]; then
          echo "FALLA  $capsula RELOJ: no se pudo medir el instante declarado"
          censo_ok=no
        elif [ "$rc_fuera" -eq 124 ]; then
          echo "FALLA  $capsula RELOJ: con el instante en $RELOJ_FUERA el PoC no termina en ${LIMITE_FALSADOR}s; no se distingue juicio de cuelgue"
          censo_ok=no
        elif [ "$rc_fuera" -eq "$vulnerable" ]; then
          echo "FALLA  $capsula RELOJ: declara 'reloj: $reloj_declarado' y su veredicto no cambia (RC $rc_fuera con el reloj real y con $RELOJ_FUERA)"
          censo_ok=no
        elif [ "$rc_fuera" -eq 3 ]; then
          # El veredicto si depende del instante, pero el sujeto ya no llega a juicio: su
          # fixture caduco. La etiqueta es verdadera y ademas hay una deuda con fecha.
          censo="$censo+caduca"
          caducan=$((caducan + 1))
        else
          censo="$censo+reloj"
        fi
        ;;
    esac
  fi

  # Las dos lineas no son dos etiquetas: son la misma afirmacion dicha dos veces, porque la
  # tabla del README define 'fuera-de-alcance' como «el efecto ES el valor de retorno... no
  # hay estado que mirar». Hasta el 17-Nov-2026 este script validaba el vocabulario y no la
  # pareja, asi que absolvia con RC 0 una capsula que declaraba `invariante: retorno` y
  # `falsador: verifica` --es decir, que su PoC mira el estado y que no hay estado que
  # mirar--. Medido: la contradiccion pasaba en verde.
  if [ "$pareja_conocida" = si ]; then
    case "$invariante:$falsador_declarado" in
      estado:fuera-de-alcance|retorno:verifica)
        echo "FALLA  $capsula PAREJA: 'invariante: $invariante' con 'falsador: $falsador_declarado'; son la misma afirmacion con signo distinto"
        censo_ok=no ;;
    esac
  fi
  [ "$censo_ok" = si ] || censo=no

  if [ "$vulnerable" -eq 0 ] && [ "$parche" -eq 1 ] && [ "$ingenuo" -eq 0 ] && [ "$roto" -eq 3 ] && [ "$controles" -eq 3 ] && [ "$censo_ok" = si ]; then
    echo "OK     $capsula (vulnerable=0 parche=1 ingenuo=0 roto=3 control=$([ "$hay_control" = si ] && echo 3 || echo n/a) falsador=$censo)"
  else
    echo "FALLA  $capsula (vulnerable=$vulnerable parche=$parche ingenuo=$ingenuo roto=$roto control=$controles falsador=$censo)"
    fallos=$((fallos + 1))
  fi
done

if [ "$rechazadas" -gt 0 ]; then
  echo ""
  echo "$rechazadas directorio(s) con prefijo de capsula no admitidos: no cuentan en el denominador."
fi

# Un cero de inventario no es un verde: sin capsulas no se verifico nada.
if [ "$total" -eq 0 ]; then
  echo "FALLA  no se encontro ninguna capsula admitida"
  exit 1
fi

echo ""
echo "$((total - fallos))/$total capsulas: ataque RC 0, parche RC 1, parche ingenuo RC 0, sujeto roto RC 3"
verifican=$(contar_declaracion "$POBLACION_FICHERO" '^falsador: verifica')
echo "$verifican/$total capsulas declaran 'falsador: verifica' y su PoC no se cree un rechazo declarado."
echo "$fronteras/$total declaran 'falsador: fuera-de-alcance' y su PoC se midio en jaula: $con_residuo con residuo."
echo "cero residuo = no escribio ni en su arbol ni por HOME/TMPDIR/XDG; ruta absoluta y red, fuera."
echo "$medidas/$total etiquetas de 'falsador:' se midieron en esta corrida: fuera-de-alcance en jaula,"
echo "verifica contra el parche mentiroso, no-medido por 'rechazos fingidos=0', roto por RC 3 y"
echo "cuelga por no terminar en ${LIMITE_CUELGA}s. Una etiqueta sin lector no se publica."

# La columna `invariante` decide, no decora: se cuenta cuantas capsulas tienen libro que
# mirar despues del rechazo y cuantas declaran que el efecto es el valor de retorno. El
# cotejo con `falsador:` ya paso capsula por capsula; esto publica la poblacion sobre la
# que se aplico.
con_estado=$(contar_declaracion "$POBLACION_FICHERO" '^invariante: estado')
con_retorno=$(contar_declaracion "$POBLACION_FICHERO" '^invariante: retorno')
echo "$con_estado/$total declaran 'invariante: estado' (el falsificador tiene libro que mirar) y"
echo "$con_retorno/$total 'invariante: retorno' (el efecto es el valor de retorno): pareja cotejada con 'falsador:' en esta corrida."
echo "dos tipos de oraculo tienen lector --estado y retorno--; un tercero se nombra TIPO y no entra"
echo "$relojes/$total declaran 'reloj:' y su veredicto se movio al instante $RELOJ_FUERA; $caducan caducan ahi."
echo "el tiempo no es un tercer tipo: es una dimension del sujeto, con lector propio desde el 17-Nov-2026."
echo "concurrencia sigue sin lector: se nombra, no se mide."

# La tabla del README y los directorios divergen en silencio: una capsula nueva sin
# fila deja el anuncio corto, y una fila sin directorio promete lo que no existe.
# Se cotejan aqui, en el mismo comando que ya se corre en cada push.
en_tabla=$(grep -oE '^\| [0-9]{3} \|' README.md | grep -oE '[0-9]{3}' | sort -u)
# Los directorios que la tabla debe anunciar son los admitidos, no todos los que ve el glob: un
# directorio rechazado en la admision no es una capsula y no tiene fila que cumplir.
en_disco=$(cut -c1-3 "$POBLACION_FICHERO" | sort -u)

if [ "$en_tabla" = "$en_disco" ]; then
  echo "OK     tabla del README: $(printf '%s\n' "$en_tabla" | grep -c .) filas, $total directorios admitidos"
else
  echo "FALLA  la tabla del README no coincide con los directorios (- solo en tabla, + solo en disco):"
  sobra=$(mktemp) || exit 1
  falta=$(mktemp) || exit 1
  printf '%s\n' "$en_tabla" >"$sobra"
  printf '%s\n' "$en_disco" >"$falta"
  comm -3 "$sobra" "$falta" | sed 's/^/       /'
  rm -f "$sobra" "$falta"
  fallos=$((fallos + 1))
fi

# Un directorio no admitido no resta en la fraccion de arriba, pero tampoco se publica en verde:
# el arbol que no pasa la aduana no es un arbol sano.
[ "$fallos" -eq 0 ] && [ "$rechazadas" -eq 0 ] || exit 1
