#!/bin/sh
set -e

host="$1"
shift
cmd="$@"

until curl -s -f "$host"; do
  >&2 echo "Keycloak is unavailable - sleeping"
  sleep 1
done

>&2 echo "Keycloak is up - executing command"
exec $cmd
