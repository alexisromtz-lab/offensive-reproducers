#!/bin/sh
# Las cuatro promesas del README, comprobadas en un solo lugar: cada capsula da
# RC 0 contra el servicio vulnerable, RC 1 contra el parche, RC 0 contra ese
# mismo parche en su variante ingenua -que debe seguir cayendo- y RC 3 contra
# `sujeto_roto.py`. El CI corre este mismo script en cada push: si aqui no sale,
# el badge y el README mienten.
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

  if [ "$vulnerable" -eq 0 ] && [ "$parche" -eq 1 ] && [ "$ingenuo" -eq 0 ] && [ "$roto" -eq 3 ]; then
    echo "OK     $capsula (vulnerable=0 parche=1 ingenuo=0 roto=3)"
  else
    echo "FALLA  $capsula (vulnerable=$vulnerable parche=$parche ingenuo=$ingenuo roto=$roto)"
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

[ "$fallos" -eq 0 ] || exit 1
