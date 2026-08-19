#!/usr/bin/env bash
# Publikuje raport bramy jako JEDEN komentarz w PR, aktualizowany przy każdym
# pushu. Mnożenie komentarzy przy każdym przebiegu jest najprostszym sposobem
# na to, żeby zespół przestał je czytać (PLAN.md §8).
#
# Wymaga: gh CLI, GH_TOKEN, PR_NUMBER.
set -euo pipefail

REPORT="${1:-gatekeeper-report.md}"
MARKER="<!-- gatekeeper:report -->"

if [[ ! -f "$REPORT" ]]; then
  echo "brak pliku raportu: $REPORT" >&2
  exit 1
fi

REPO="${GITHUB_REPOSITORY:?brak GITHUB_REPOSITORY}"
PR="${PR_NUMBER:?brak PR_NUMBER}"

existing_id="$(
  gh api "repos/${REPO}/issues/${PR}/comments" --paginate \
    --jq "map(select(.body | contains(\"${MARKER}\"))) | .[0].id // empty"
)"

if [[ -n "$existing_id" ]]; then
  gh api -X PATCH "repos/${REPO}/issues/comments/${existing_id}" \
    -F body=@"$REPORT" >/dev/null
  echo "zaktualizowano komentarz ${existing_id}"
else
  gh api -X POST "repos/${REPO}/issues/${PR}/comments" \
    -F body=@"$REPORT" >/dev/null
  echo "utworzono nowy komentarz"
fi
