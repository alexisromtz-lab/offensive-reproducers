# offensive-reproducers

Laboratorios sintéticos de seguridad ofensiva. Cada cápsula es un fallo real,
reconstruido desde cero en código propio, con su exploit determinista y su parche.
Todo corre en menos de diez segundos, sin dependencias externas y sin red externa.

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

## Contrato de cada cápsula

```
NNN-<vector>/
├── README.md           # hipótesis, anatomía del fallo, impacto y remedio
├── app_vulnerable.py   # servicio mínimo sintético, sólo biblioteca estándar
├── exploit_poc.py      # PoC determinista: RC 0 explota, RC 1 bloqueado
└── patch_secure.py     # corrección canónica + el parche ingenuo, para refutarlo
```

Cuatro reglas que se comprueban, no se prometen:

1. **Determinista.** Dos corridas, el mismo resultado. Sin reloj, sin azar, sin red externa.
   Las cápsulas que necesitan un servicio levantan uno efímero en `127.0.0.1` y lo apagan
   al terminar: el aislamiento es parte del sujeto, no una promesa.
2. **Autocontenida.** Sólo biblioteca estándar. Nada que instalar.
3. **Falsable.** El PoC decide por código de salida, no por lo que imprime.
4. **Dual.** La misma corrida contra el parche debe fallar de forma determinista.

## Verificar todo

```bash
for capsula in [0-9][0-9][0-9]-*/; do
  cd "$capsula"
  python3 exploit_poc.py >/dev/null;                 vulnerable=$?
  python3 exploit_poc.py --app patch_secure.py >/dev/null; parche=$?
  cd ..
  if [ "$vulnerable" -eq 0 ] && [ "$parche" -eq 1 ]; then
    echo "OK: $capsula"
  else
    echo "FALLA: $capsula (vulnerable=$vulnerable parche=$parche)"
  fi
done
```

## Licencia

MIT. Ver [LICENSE](LICENSE).
