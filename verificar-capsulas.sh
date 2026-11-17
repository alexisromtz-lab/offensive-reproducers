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
# La decima: todo valor que el censo publica tiene lector. `no-medido`, `roto` y `cuelga`
# pasaban por un `;;` vacio mientras el censo los imprimia como datos. Desde el 17-Nov-2026
# se miden contra el mismo falsificador que los provoca: un vocabulario que crece sin lector
# es prosa con formato de dato.
set -u

# `falsador: cuelga` no deja codigo de salida, asi que su unica medida posible es un reloj.
# Medido el 17-Nov-2026: 009 no termina ni en 20 s; el limite se queda corto y se publica.
LIMITE_CUELGA=5
LIMITE_FALSADOR=8

# Cuenta las lineas de diferencia entre el arbol de la capsula antes y despues de correr su
# PoC en una jaula temporal. El limite esta declarado: mide lo que queda DENTRO de la jaula;
# un PoC que escriba con ruta absoluta fuera de ella no se ve aqui, y por eso la jaula se
# monta con la capsula como subdirectorio --`../x` sigue cayendo dentro--.
residuo_en_jaula() {
  cap=$1
  jaula=$(mktemp -d "${TMPDIR:-/tmp}/frontera.XXXXXX") || { echo 99; return 0; }
  cp -R "${cap%/}" "$jaula/" || { rm -rf "$jaula"; echo 99; return 0; }
  sub="$jaula/${cap%/}"
  (cd "$sub" && find . -type f ! -name '*.pyc' ! -path '*/__pycache__/*' | LC_ALL=C sort | xargs cksum) >"$jaula/antes" 2>/dev/null
  (cd "$sub" && python3 exploit_poc.py >/dev/null 2>&1)
  (cd "$sub" && find . -type f ! -name '*.pyc' ! -path '*/__pycache__/*' | LC_ALL=C sort | xargs cksum) >"$jaula/despues" 2>/dev/null
  escrito=$(diff "$jaula/antes" "$jaula/despues" 2>/dev/null | grep -c '^[<>]')
  rm -rf "$jaula"
  echo "${escrito:-99}"
}

# Corre el PoC de una capsula contra un sujeto con limite de segundos y publica
# "RC=<rc> FINGIDOS=<n>". El falsificador ya dice cuantos rechazos fingidos vio --con cero
# fingidos un RC 0 no absolvio nada-- y ese numero, que hasta el 17-Nov-2026 se tiraba a
# /dev/null, es lo que decide si su veredicto significa algo. RC 124 si no termina.
con_limite() {
  cap=$1
  sujeto=$2
  limite=$3
  python3 - "$cap" "$sujeto" "$limite" <<'PY'
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
}

# Sin esta prueba el cotejo seria otra marca sin lector: nadie sabria si sigue mirando. Se
# copia una capsula que hoy certifica, se le cambia `invariante:` por `retorno` --dejando
# `falsador: verifica`, que es la contradiccion-- y se exige RC distinto de 0 con la palabra
# PAREJA en la salida; despues se restaura la linea original y se exige RC 0. Dos
# direcciones: caza la mentira y no acusa a la capsula sana.
self_test() {
  origen=$(cd "$(dirname "$0")" && pwd) || return 1
  capsula=$(cd "$origen" && ls -d [0-9][0-9][0-9]-*/ 2>/dev/null | while read -r c; do
    if grep -q '^falsador: verifica' "$c"README.md 2>/dev/null; then echo "$c"; break; fi
  done)
  if [ -z "$capsula" ]; then
    echo "FALLA  --self-test necesita al menos una capsula con 'falsador: verifica'"
    return 2
  fi

  jaula=$(mktemp -d "${TMPDIR:-/tmp}/pareja.XXXXXX") || return 1
  cp "$origen/verificar-capsulas.sh" "$origen/sujeto_roto.py" "$origen/parche_mentiroso.py" "$jaula/" || return 1
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
  echo "OK     --self-test: 'invariante: retorno' con 'falsador: verifica' -> RC $rc_contradiccion nombrando PAREJA; la misma capsula con lo que declara hoy -> RC 0"

  # Segundo brazo, la frontera: una capsula que declara no tener libro y cuyo PoC escribe uno
  # tiene que salir roja nombrando FRONTERA; la misma capsula sin escribir, verde. Medido el
  # 17-Nov-2026: las cinco capsulas con `fuera-de-alcance` dejan cero residuo, asi que la
  # frontera era una promesa sin predicado. Aqui se le pone predicado y falsador propio.
  jaula=$(mktemp -d "${TMPDIR:-/tmp}/self-frontera.XXXXXX") || return 1
  cp "$origen/verificar-capsulas.sh" "$origen/sujeto_roto.py" "$origen/parche_mentiroso.py" "$jaula/" || return 1
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
  echo "OK     --self-test: PoC que escribe con 'falsador: fuera-de-alcance' -> RC $rc_residuo nombrando FRONTERA; el mismo PoC sin escribir -> RC 0"

  # Tercer brazo, el vocabulario: una etiqueta del censo que no se mide es prosa con formato
  # de dato. Se plantan las tres mentiras --mas una verdad del mismo tipo-- y se exige que
  # cada mentira salga roja nombrando su etiqueta y que la verdad no sea acusada.
  jaula=$(mktemp -d "${TMPDIR:-/tmp}/etiquetas.XXXXXX") || return 1
  cp "$origen/verificar-capsulas.sh" "$origen/sujeto_roto.py" "$origen/parche_mentiroso.py" "$jaula/" || return 1
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
  echo "OK     --self-test: 'no-medido' con fingidos>0, 'roto' con RC 0, 'cuelga' que termina e 'invariante: tiempo' -> RC $rc_etiquetas nombrando NO-MEDIDO, ROTO, CUELGA y TIPO; el 'roto' verdadero -> RC 0"
  return 0
}

case "${1:-}" in
  --self-test) self_test; exit $? ;;
  "") ;;
  *) echo "uso: $0 [--self-test]"; exit 20 ;;
esac

fallos=0
total=0
fronteras=0
con_residuo=0
medidas=0

for capsula in [0-9][0-9][0-9]-*/; do
  [ -d "$capsula" ] || continue
  total=$((total + 1))

  # Las dos lineas se leen, y la frontera se mide, sobre el estado PRISTINO: antes de que esta
  # corrida toque la capsula. Medida despues, la foto «antes» ya incluiria lo que el propio PoC
  # acaba de escribir en el arbol de trabajo y el residuo seria invisible --el falso verde que
  # esta regla existe para cazar, cometido por la regla misma--.
  invariante=$(sed -n 's/^invariante: *//p' "$capsula"README.md 2>/dev/null | head -1)
  falsador_declarado=$(sed -n 's/^falsador: *//p' "$capsula"README.md 2>/dev/null | head -1)
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
        echo "FALLA  $capsula FRONTERA: declara que no hay libro que mirar y su PoC escribio en la jaula ($escrito linea(s) de diferencia)"
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

# Un cero de inventario no es un verde: sin capsulas no se verifico nada.
if [ "$total" -eq 0 ]; then
  echo "FALLA  no se encontro ninguna capsula"
  exit 1
fi

echo ""
echo "$((total - fallos))/$total capsulas: ataque RC 0, parche RC 1, parche ingenuo RC 0, sujeto roto RC 3"
verifican=$(grep -l '^falsador: verifica' [0-9][0-9][0-9]-*/README.md 2>/dev/null | wc -l | tr -d ' ')
echo "$verifican/$total capsulas declaran 'falsador: verifica' y su PoC no se cree un rechazo declarado."
echo "$fronteras/$total declaran 'falsador: fuera-de-alcance' y su PoC se midio en jaula: $con_residuo con residuo."
echo "cero residuo = la frontera se comprobo en esta corrida; no es una promesa del README."
echo "$medidas/$total etiquetas de 'falsador:' se midieron en esta corrida: fuera-de-alcance en jaula,"
echo "verifica contra el parche mentiroso, no-medido por 'rechazos fingidos=0', roto por RC 3 y"
echo "cuelga por no terminar en ${LIMITE_CUELGA}s. Una etiqueta sin lector no se publica."

# La columna `invariante` decide, no decora: se cuenta cuantas capsulas tienen libro que
# mirar despues del rechazo y cuantas declaran que el efecto es el valor de retorno. El
# cotejo con `falsador:` ya paso capsula por capsula; esto publica la poblacion sobre la
# que se aplico.
con_estado=$(grep -l '^invariante: estado' [0-9][0-9][0-9]-*/README.md 2>/dev/null | wc -l | tr -d ' ')
con_retorno=$(grep -l '^invariante: retorno' [0-9][0-9][0-9]-*/README.md 2>/dev/null | wc -l | tr -d ' ')
echo "$con_estado/$total declaran 'invariante: estado' (el falsificador tiene libro que mirar) y"
echo "$con_retorno/$total 'invariante: retorno' (el efecto es el valor de retorno): pareja cotejada con 'falsador:' en esta corrida."
echo "dos tipos de oraculo tienen lector; un tercero --tiempo, concurrencia-- se nombra TIPO y no entra"

# La tabla del README y los directorios divergen en silencio: una capsula nueva sin
# fila deja el anuncio corto, y una fila sin directorio promete lo que no existe.
# Se cotejan aqui, en el mismo comando que ya se corre en cada push.
en_tabla=$(grep -oE '^\| [0-9]{3} \|' README.md | grep -oE '[0-9]{3}' | sort -u)
en_disco=$(ls -d [0-9][0-9][0-9]-*/ 2>/dev/null | cut -c1-3 | sort -u)

if [ "$en_tabla" = "$en_disco" ]; then
  echo "OK     tabla del README: $total filas, $total directorios"
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

[ "$fallos" -eq 0 ] || exit 1
