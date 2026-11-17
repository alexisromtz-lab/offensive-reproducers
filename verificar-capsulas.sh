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
set -u

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
  # rechazo; un RC 1 significa que se lo creyo. Los otros valores son el censo publicado
  # (fuera-de-alcance, no-medido, cuelga, roto) y no se ejecutan: 009 no termina y 004
  # rompe el sujeto. Sin lector esa afirmacion seria prosa y nadie la refutaria.
  # (las declaraciones ya se leyeron sobre el estado pristino, con la frontera medida)
  censo_ok=si
  pareja_conocida=si
  censo="$falsador_declarado"
  case "$invariante" in
    estado|retorno) ;;
    *) echo "FALLA  $capsula sin declarar 'invariante: estado|retorno'"; censo_ok=no; pareja_conocida=no ;;
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
      fi
      ;;
    no-medido|cuelga|roto) ;;
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
echo "$verifican/$total capsulas declaran 'falsador: verifica' y su PoC no se cree un rechazo declarado;"
echo "el resto publica su censo en el README (fuera-de-alcance · no-medido · cuelga · roto)."
echo "$fronteras/$total declaran 'falsador: fuera-de-alcance' y su PoC se midio en jaula: $con_residuo con residuo."
echo "cero residuo = la frontera se comprobo en esta corrida; no es una promesa del README."

# La columna `invariante` decide, no decora: se cuenta cuantas capsulas tienen libro que
# mirar despues del rechazo y cuantas declaran que el efecto es el valor de retorno. El
# cotejo con `falsador:` ya paso capsula por capsula; esto publica la poblacion sobre la
# que se aplico.
con_estado=$(grep -l '^invariante: estado' [0-9][0-9][0-9]-*/README.md 2>/dev/null | wc -l | tr -d ' ')
con_retorno=$(grep -l '^invariante: retorno' [0-9][0-9][0-9]-*/README.md 2>/dev/null | wc -l | tr -d ' ')
echo "$con_estado/$total declaran 'invariante: estado' (el falsificador tiene libro que mirar) y"
echo "$con_retorno/$total 'invariante: retorno' (el efecto es el valor de retorno): pareja cotejada con 'falsador:' en esta corrida."

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
