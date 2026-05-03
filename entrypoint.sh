#!/bin/bash
set -e

# Create a user inside the container that matches the host UID/GID.
# This ensures volume-mounted files are accessible and tools like whoami work.
HOST_UID="${HOST_UID:-1000}"
HOST_GID="${HOST_GID:-1000}"
HOST_USER="${HOST_USER:-hunter}"
HOST_HOME="${HOST_HOME:-/home/$HOST_USER}"

if ! getent passwd "$HOST_UID" >/dev/null 2>&1; then
    groupadd -f -g "$HOST_GID" "$HOST_USER" 2>/dev/null || true
    useradd -u "$HOST_UID" -g "$HOST_GID" -d "$HOST_HOME" -s /bin/bash "$HOST_USER" 2>/dev/null || true
fi

export HOME="$HOST_HOME"

exec gosu "$HOST_UID:$HOST_GID" "$@"
