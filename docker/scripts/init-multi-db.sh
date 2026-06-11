#!/bin/sh
set -eu

# Bootstrap three DBs in the same Postgres for the dev compose stack.
for db in auth account tx; do
  echo "Creating database $db ..."
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE $db;
EOSQL
done

# Apply migrations.
for db in auth account tx; do
  for f in /migrations/$db/*.sql; do
    [ -f "$f" ] || continue
    echo "Applying $f to $db ..."
    psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$db" -f "$f"
  done
done

echo "Multi-DB init complete."
