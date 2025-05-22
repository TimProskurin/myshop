#!/bin/sh
set -e

TIMEOUT=${TIMEOUT:-30}

wait_for() {
  local host="$1"
  local port="$2"
  local timeout="$3"

  echo "Ожидание $host:$port (таймаут: ${timeout}s)..."
  timeout $timeout sh -c "until nc -z $host $port; do sleep 1; done"
}

# Исправленный цикл обработки аргументов
while [ $# -gt 0 ]; do
  case "$1" in
    --timeout=*)
      TIMEOUT="${1#*=}"
      shift
      ;;
    *)
      if [ "$1" = "--" ]; then
        shift
        break
      fi
      host_port="$1"
      host=$(echo "$host_port" | cut -d ':' -f1)
      port=$(echo "$host_port" | cut -d ':' -f2)
      wait_for "$host" "$port" "$TIMEOUT"
      shift
      ;;
  esac
done

exec "$@"