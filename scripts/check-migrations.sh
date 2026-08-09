#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Check the shape of migrations/ against the project's migration policy.
#
# sqlx enforces none of this. It classifies each file independently by
# suffix and performs no cross-file validation, so every failure below is
# one it would accept and then surprise somebody with later.
#
# Rules:
#
#   1. Exactly one up-migration per version. Two files claiming the same
#      version both resolve as up-migrations, and the version is then
#      applied twice in a single pass. This is the failure mode of a
#      half-finished rename, where `0001_foo.sql` and `0001_foo.up.sql`
#      briefly coexist.
#
#   2. Every version above 1 is a reversible `.up.sql`/`.down.sql` pair.
#      Two reasons. `sqlx migrate add` takes its default style from the
#      newest existing migration, so while version 1
#      is simple, adding a migration without `-r` silently produces an
#      irreversible one. And an `.up.sql` with no companion is worse than
#      an error: `Migrator::undo` filters to `is_down_migration()`, so a
#      version with no down file is skipped in silence and its
#      `_sqlx_migrations` row survives, which makes the apply/revert/apply
#      round trip pass while reverting nothing.
#
#   3. Version 1 may be either style. It predates the policy. Keeping it
#      simple is a deliberate choice while the schema is still being
#      amended in place, and renaming it later is a no-op as far as sqlx
#      is concerned: the checksum is taken over file contents, and the
#      recorded description is the same either way.
#
# Usage:
#   ./scripts/check-migrations.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

MIGRATIONS="migrations"
FAIL=0

fail() {
    echo "error: $*" >&2
    FAIL=1
}

if [ ! -d "$MIGRATIONS" ]; then
    fail "no $MIGRATIONS directory"
    exit 1
fi

shopt -s nullglob
files=("$MIGRATIONS"/*.sql)
shopt -u nullglob

if [ ${#files[@]} -eq 0 ]; then
    fail "$MIGRATIONS contains no .sql files"
    exit 1
fi

# version -> space-separated basenames of its up-migrations
declare -A ups
# version -> 1 when a .down.sql exists
declare -A downs

for path in "${files[@]}"; do
    name="$(basename "$path")"

    # sqlx ignores anything that is not <VERSION>_<DESCRIPTION>.sql, so a
    # file it would skip is a file that silently does nothing.
    if [[ ! "$name" =~ ^([0-9]+)_ ]]; then
        fail "$name has no integer version prefix; sqlx would ignore it entirely"
        continue
    fi
    version="${BASH_REMATCH[1]}"
    # Strip leading zeros for comparison, keeping the original for messages.
    number=$((10#$version))

    case "$name" in
        *.down.sql) downs["$number"]=1 ;;
        *.up.sql | *.sql) ups["$number"]="${ups[$number]:-} $name" ;;
    esac
done

for version in "${!ups[@]}"; do
    # shellcheck disable=SC2206
    names=(${ups[$version]})

    if [ ${#names[@]} -gt 1 ]; then
        fail "version $version has ${#names[@]} up-migrations (${names[*]}); sqlx would apply it more than once"
    fi

    if [ "$version" -eq 1 ]; then
        # Rule 3: either style is allowed, but a half-done pair is not.
        if [[ "${names[0]}" == *.up.sql ]] && [ -z "${downs[1]:-}" ]; then
            fail "version 1 is ${names[0]} with no .down.sql companion"
        fi
        continue
    fi

    if [[ "${names[0]}" != *.up.sql ]]; then
        fail "version $version is ${names[0]}, a simple migration; every version from 2 onward must be a reversible pair (use: sqlx migrate add -r <name>)"
    elif [ -z "${downs[$version]:-}" ]; then
        fail "version $version has ${names[0]} but no .down.sql companion; undo would skip it in silence"
    fi
done

# A .down.sql with nothing to undo is a file sqlx will never run.
for version in "${!downs[@]}"; do
    if [ -z "${ups[$version]:-}" ]; then
        fail "version $version has a .down.sql but no up-migration"
    fi
done

if [ "$FAIL" -eq 0 ]; then
    echo "migrations/: ${#ups[@]} version(s), shape OK"
fi

exit "$FAIL"
