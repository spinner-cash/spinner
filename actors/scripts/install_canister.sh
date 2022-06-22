#!/usr/bin/env bash

MODE=install
test "$1" = "--install" && MODE=install && shift
test "$1" = "--upgrade" && MODE=upgrade && shift
test "$1" = "--reinstall" && MODE=reinstall && shift
CANISTER_IDS_JSON="canister_ids.json"
CANISTER=$1
NETWORK=${2:-local}
test "$NETWORK" = "local" && CANISTER_IDS_JSON=".dfx/local/${CANISTER_IDS_JSON}"

echo "To ${MODE} canister $CANISTER on network $NETWORK"

test ! -f "./dist/${NETWORK}" && echo ./dist/${NETWORK} does not exist && exit 1

CANISTER_ID=$(cat "$CANISTER_IDS_JSON" | jq -r ".${CANISTER}.${NETWORK}")
test "${CANISTER_ID}" = "null" && echo "$CANISTER does not exist on $NETWORK network" && exit 1

CANISTER_IDS_FILE=$(mktemp --tmpdir canister-ids.XXXXXXXX)
cat "$CANISTER_IDS_JSON" | jq -c "keys[] as \$k | [\$k, (.[\$k] .$NETWORK)]" \
    | sed -e 's/\["\([^"]*\)","\([^"]*\)"\]/let canister_\1 = principal "\2";/g' >"$CANISTER_IDS_FILE"

ICREPL_FILE=$(mktemp ic-repl.XXXXXXXX)
cat >"$ICREPL_FILE" <<END
  identity private "dist/identity.pem";
  load "./dist/${NETWORK}";
  load "./scripts/functions";
  load "$CANISTER_IDS_FILE";
  load "./scripts/install_${CANISTER}";
  install_${CANISTER}(variant { $MODE });
END

ic-repl "$ICREPL_FILE" >/dev/null
test "$?" != "0" && rm -f "$CANISTER_IDS_FILE" "$ICREPL_FILE" && exit 1
rm -f "$CANISTER_IDS_FILE" "$ICREPL_FILE"
