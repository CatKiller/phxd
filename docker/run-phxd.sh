#!/bin/sh
# Docker entrypoint: runs phxd as an unprivileged user.
#
# Started as root (the default), it:
#   1. picks the user to run phxd as: $PHXD_UID/$PHXD_GID if set, otherwise
#      the owner of the shared files directory if that isn't root (so a
#      bind-mounted host directory keeps its ownership), otherwise the
#      image's "phxd" user (10001);
#   2. gives that user the database/log directory and the files directory,
#      if it doesn't own them yet (e.g. data from older, root-run images);
#   3. if the TLS certificate or key isn't readable by that user (Let's
#      Encrypt keys are root-only), copies them into a root-owned directory
#      only phxd's group can read, and keeps the copies up to date so
#      renewed certificates are still picked up without a restart;
#   4. runs phxd as that user, unable to regain privileges.
# Started as a non-root user (docker run --user ...), it just runs phxd.
set -eu

if [ "$(id -u)" != "0" ]; then
	exec "$@"
fi

cd /app

# Settings as phxd will see them (config.py + phxd.yaml).
settings=$(python -c '
import os, config
for value in ( config.DB_FILE_BASEPATH , config.FILE_ROOT , config.TLS_CERT , config.TLS_KEY ):
    print( os.path.abspath( value ) if value else "" )
')
db_dir=$(printf '%s\n' "$settings" | sed -n 1p)
files_dir=$(printf '%s\n' "$settings" | sed -n 2p)
tls_cert=$(printf '%s\n' "$settings" | sed -n 3p)
tls_key=$(printf '%s\n' "$settings" | sed -n 4p)

mkdir -p "$db_dir" "$files_dir"

# 1. Who to run as.
run_uid=${PHXD_UID:-}
run_gid=${PHXD_GID:-}
if [ -z "$run_uid" ]; then
	files_uid=$(stat -c %u "$files_dir")
	if [ "$files_uid" != "0" ]; then
		run_uid=$files_uid
		run_gid=${run_gid:-$(stat -c %g "$files_dir")}
	else
		run_uid=$(id -u phxd)
	fi
fi
run_gid=${run_gid:-$(id -g phxd)}
if [ "$run_uid" = "0" ]; then
	echo "phxd: refusing to run as root (PHXD_UID=0)" >&2
	exit 1
fi

# 2. Data directories.
for dir in "$db_dir" "$files_dir"; do
	if [ "$(stat -c %u "$dir")" != "$run_uid" ]; then
		echo "phxd: giving $dir to uid $run_uid"
		chown -R "$run_uid:$run_gid" "$dir" || {
			echo "phxd: cannot change the owner of $dir. With --cap-drop ALL, also pass" >&2
			echo "      --cap-add CHOWN --cap-add SETUID --cap-add SETGID" >&2
			exit 1
		}
	fi
done

# 3. TLS certificate and key.
can_read() {
	setpriv --reuid="$run_uid" --regid="$run_gid" --clear-groups test -r "$1"
}
if [ -n "$tls_cert" ] && [ -n "$tls_key" ] && ! { can_read "$tls_cert" && can_read "$tls_key"; }; then
	tls_dir=/run/phxd-tls
	# Owned by root: phxd can read the copies but can't replace them (or
	# swap in links for root to write through).
	rm -rf "$tls_dir"
	mkdir -m 0750 "$tls_dir"
	chown "root:$run_gid" "$tls_dir"
	copy_one() {
		# $1 = source, $2 = copy. Replaced atomically, only when changed.
		if [ -r "$1" ] && ! cmp -s "$1" "$2"; then
			cp "$1" "$2.new"
			chown "root:$run_gid" "$2.new"
			chmod 0640 "$2.new"
			mv -f "$2.new" "$2"
		fi
	}
	copy_tls() {
		copy_one "$tls_key" "$tls_dir/key.pem"
		copy_one "$tls_cert" "$tls_dir/cert.pem"
	}
	copy_tls
	(
		while sleep "${PHXD_TLS_COPY_INTERVAL:-300}"; do
			copy_tls || true
		done
	) &
	export PHXD_TLS_CERT="$tls_dir/cert.pem"
	export PHXD_TLS_KEY="$tls_dir/key.pem"
fi

# 4. Run phxd unprivileged.
exec setpriv --reuid="$run_uid" --regid="$run_gid" --clear-groups --no-new-privs -- "$@"
