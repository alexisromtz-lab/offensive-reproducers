#!/bin/sh
# Las cinco promesas del README, comprobadas en un solo lugar: cada capsula da
# RC 0 contra el servicio vulnerable, RC 1 contra el parche, RC 0 contra ese
# mismo parche en su variante ingenua -que debe seguir cayendo-, RC 3 contra
# `sujeto_roto.py` y RC 3 contra cada `control_*.py` que la capsula declare. El CI
# corre este mismo script en cada push: si aqui no sale, el badge y el README mienten.
set -u

fallos=0
total=0

for capsula in [0-9][0-9][0-9]-*/; do
  [ -d "$capsula" ] || continue
  total=$((total + 1))

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
  invariante=$(sed -n 's/^invariante: *//p' "$capsula"README.md 2>/dev/null | head -1)
  falsador_declarado=$(sed -n 's/^falsador: *//p' "$capsula"README.md 2>/dev/null | head -1)
  censo_ok=si
  censo="$falsador_declarado"
  case "$invariante" in
    estado|retorno) ;;
    *) echo "FALLA  $capsula sin declarar 'invariante: estado|retorno'"; censo_ok=no ;;
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
    fuera-de-alcance|no-medido|cuelga|roto) ;;
    *) echo "FALLA  $capsula falsador: valor no reconocido '$falsador_declarado'"; censo_ok=no ;;
  esac
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
