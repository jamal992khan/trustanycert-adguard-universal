#!/system/bin/sh
# Post-boot APEX re-injection; also invoked by WebUI with FAST=1 to refresh
# the trust store after a cert add/delete without waiting for reboot.

MODDIR=${0%/*}
LOG_FILE="/data/local/tmp/trustanycert.log"
CERT_DIR="${MODDIR}/system/etc/security/cacerts"
TEMP_DIR="/data/adb/trustanycert-apex-cacerts"
LEGACY_TEMP_DIR="/data/local/tmp/trustanycert-apex-ca"
APEX_CACERTS="/apex/com.android.conscrypt/cacerts"
APEX_SOURCE=""
SYSTEM_CACERTS="/system/etc/security/cacerts"
SYSTEM_STAGE="/data/adb/trustanycert-system-cacerts"
MOUNT_MARKER=".trustanycert-owner"
MOUNT_OWNER="trustanycert-v1"
SYSTEM_MARKER=".trustanycert-system-owner"
FAST_MODE="${FAST:-0}"  # WebUI passes FAST=1 to skip the boot-wait loop

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [service] $1" >> "$LOG_FILE"
}

log ""
log "════════════════════════════════════════════════════"
log "Service script started (FAST=$FAST_MODE)"

API=$(getprop ro.build.version.sdk)
log "Android API: $API"

if [ "$FAST_MODE" != "1" ]; then
    count=0
    while [ "$(getprop sys.boot_completed)" != "1" ] && [ $count -lt 60 ]; do
        sleep 1
        count=$((count + 1))
    done
    log "Boot completed (${count}s)"
fi

# Magic Mount already covers /system/etc/security/cacerts on older Android
if [ "$API" -lt 34 ]; then
    log "Android < 14, APEX injection not needed"
    exit 0
fi

mkdir -p "$CERT_DIR"
CERT_COUNT=$(find "$CERT_DIR" -maxdepth 1 -type f -name "*.[0-9]*" 2>/dev/null | wc -l)
CERT_COUNT=$(echo "$CERT_COUNT" | tr -d ' ')

if [ "$CERT_COUNT" = "0" ] || [ -z "$CERT_COUNT" ]; then
    log "No certificates present in module. Nothing to inject."
    log "Tip: upload a certificate via the WebUI."
    exit 0
fi

log "User certificates: $CERT_COUNT"

for candidate in /apex/com.android.conscrypt@*/cacerts; do
    [ -d "$candidate" ] || continue
    SOURCE_COUNT=$(find "$candidate" -maxdepth 1 -type f -name '*.[0-9]*' 2>/dev/null | wc -l)
    SOURCE_COUNT=$(echo "$SOURCE_COUNT" | tr -d ' ')
    if [ "$SOURCE_COUNT" -gt 10 ]; then
        APEX_SOURCE="$candidate"
        break
    fi
done

if [ -z "$APEX_SOURCE" ]; then
    log "ERROR: Could not find an untouched versioned Conscrypt certificate store; leaving mounts unchanged"
    exit 1
fi

log "Using stock certificate source: $APEX_SOURCE"
log "Stock certificates available: $SOURCE_COUNT"

# Rebuild the shared staging directory so WebUI-driven cert changes are reflected
log "Rebuilding shared certificate view..."

unmount_apex_namespace() {
    if [ "$1" = "self" ]; then
        count=0
        while { [ "$(cat "$APEX_CACERTS/$MOUNT_MARKER" 2>/dev/null)" = "$MOUNT_OWNER" ] || awk '$5=="/apex/com.android.conscrypt/cacerts" && ($4=="/local/tmp/trustanycert-apex-ca" || $4=="/adb/trustanycert-apex-cacerts") {found=1} END {exit !found}' /proc/self/mountinfo; } && [ "$count" -lt 16 ]; do
            umount -l "$APEX_CACERTS" 2>/dev/null || break
            count=$((count + 1))
        done
    else
        nsenter --mount="$1" -- sh -c 'count=0; while { [ "$(cat /apex/com.android.conscrypt/cacerts/.trustanycert-owner 2>/dev/null)" = "trustanycert-v1" ] || awk "\$5==\"/apex/com.android.conscrypt/cacerts\" && (\$4==\"/local/tmp/trustanycert-apex-ca\" || \$4==\"/adb/trustanycert-apex-cacerts\") {found=1} END {exit !found}" /proc/self/mountinfo; } && [ "$count" -lt 16 ]; do umount -l /apex/com.android.conscrypt/cacerts 2>/dev/null || break; count=$((count + 1)); done' 2>/dev/null
    fi
}

unmount_system_namespace() {
    if [ "$1" = "self" ]; then
        count=0
        while { [ "$(cat "$SYSTEM_CACERTS/$SYSTEM_MARKER" 2>/dev/null)" = "$MOUNT_OWNER" ] || awk '$5=="/system/etc/security/cacerts" && $4=="/adb/trustanycert-system-cacerts" {found=1} END {exit !found}' /proc/self/mountinfo; } && [ "$count" -lt 16 ]; do
            umount -l "$SYSTEM_CACERTS" 2>/dev/null || break
            count=$((count + 1))
        done
    else
        nsenter --mount="$1" -- sh -c 'count=0; while { [ "$(cat /system/etc/security/cacerts/.trustanycert-system-owner 2>/dev/null)" = "trustanycert-v1" ] || awk "\$5==\"/system/etc/security/cacerts\" && \$4==\"/adb/trustanycert-system-cacerts\" {found=1} END {exit !found}" /proc/self/mountinfo; } && [ "$count" -lt 16 ]; do umount -l /system/etc/security/cacerts 2>/dev/null || break; count=$((count + 1)); done' 2>/dev/null
    fi
}

unmount_apex_namespace self
unmount_system_namespace self
unmount_apex_namespace /proc/1/ns/mnt
unmount_system_namespace /proc/1/ns/mnt

for zygote in zygote zygote64 webview_zygote; do
    for PID in $(pidof "$zygote" 2>/dev/null); do
        unmount_apex_namespace "/proc/$PID/ns/mnt"
        unmount_system_namespace "/proc/$PID/ns/mnt"
    done
done

for pkg in com.android.settings com.google.android.gms com.android.chrome com.android.vending \
           com.adguard.android com.proxy.pin com.network.proxy com.network.proxy.flutter \
           tech.httptoolkit.android.v1 com.reqable.android; do
    for PID in $(pidof "$pkg" 2>/dev/null); do
        unmount_apex_namespace "/proc/$PID/ns/mnt"
        unmount_system_namespace "/proc/$PID/ns/mnt"
    done
done

count=0
while [ "$(cat "$LEGACY_TEMP_DIR/$MOUNT_MARKER" 2>/dev/null)" = "$MOUNT_OWNER" ] && [ "$count" -lt 16 ]; do
    umount -l "$LEGACY_TEMP_DIR" 2>/dev/null || break
    count=$((count + 1))
done

mkdir -p "$TEMP_DIR"
find "$TEMP_DIR" -maxdepth 1 -type f -exec rm -f {} \; 2>/dev/null
echo "$MOUNT_OWNER" > "$TEMP_DIR/$MOUNT_MARKER"
chmod 0644 "$TEMP_DIR/$MOUNT_MARKER"

cp -a "$APEX_SOURCE"/*.[0-9]* "$TEMP_DIR/" 2>/dev/null
ORIG_COUNT=$(find "$TEMP_DIR" -maxdepth 1 -type f -name '*.[0-9]*' 2>/dev/null | wc -l)
ORIG_COUNT=$(echo "$ORIG_COUNT" | tr -d ' ')
if [ "$ORIG_COUNT" -lt 10 ]; then
    log "ERROR: Stock certificate copy failed; refusing to replace APEX with an incomplete store"
    exit 1
fi

for CERT_FILE in "$CERT_DIR"/*.[0-9]*; do
    [ -f "$CERT_FILE" ] || continue
    cp -f "$CERT_FILE" "$TEMP_DIR/$(basename "$CERT_FILE")"
done

chown -R 0:0 "$TEMP_DIR"
chmod 755 "$TEMP_DIR"
chmod 644 "$TEMP_DIR"/*

APEX_CONTEXT=$(ls -Zd "$APEX_CACERTS" 2>/dev/null | awk '{print $1}')
if [ -n "$APEX_CONTEXT" ] && [ "$APEX_CONTEXT" != "?" ]; then
    chcon -R "$APEX_CONTEXT" "$TEMP_DIR" 2>/dev/null
fi

mkdir -p "$SYSTEM_STAGE"
find "$SYSTEM_STAGE" -maxdepth 1 -type f -exec rm -f {} \; 2>/dev/null
echo "$MOUNT_OWNER" > "$SYSTEM_STAGE/$SYSTEM_MARKER"
cp -a "$SYSTEM_CACERTS"/*.[0-9]* "$SYSTEM_STAGE/" 2>/dev/null
SYSTEM_COUNT=$(find "$SYSTEM_STAGE" -maxdepth 1 -type f -name '*.[0-9]*' 2>/dev/null | wc -l)
SYSTEM_COUNT=$(echo "$SYSTEM_COUNT" | tr -d ' ')
if [ "$SYSTEM_COUNT" -lt 10 ]; then
    log "ERROR: Stock /system certificate copy failed; leaving /system store untouched"
else
    for CERT_FILE in "$CERT_DIR"/*.[0-9]*; do
        [ -f "$CERT_FILE" ] || continue
        cp -f "$CERT_FILE" "$SYSTEM_STAGE/$(basename "$CERT_FILE")"
    done
    chown -R 0:0 "$SYSTEM_STAGE"
    chmod 755 "$SYSTEM_STAGE"
    chmod 644 "$SYSTEM_STAGE"/*
    SYSTEM_CONTEXT=$(ls -Zd "$SYSTEM_CACERTS" 2>/dev/null | awk '{print $1}')
    if [ -n "$SYSTEM_CONTEXT" ] && [ "$SYSTEM_CONTEXT" != "?" ]; then
        chcon -R "$SYSTEM_CONTEXT" "$SYSTEM_STAGE" 2>/dev/null
    fi
fi

log "Injecting to namespaces..."
mount --bind "$TEMP_DIR" "$APEX_CACERTS" 2>/dev/null && log "✓ Global mount"

mount_apex_namespace() {
    nsenter --mount="$1" -- sh -c '[ "$(cat /apex/com.android.conscrypt/cacerts/.trustanycert-owner 2>/dev/null)" = "trustanycert-v1" ] || mount --bind /data/adb/trustanycert-apex-cacerts /apex/com.android.conscrypt/cacerts' 2>/dev/null
}

mount_system_namespace() {
    nsenter --mount="$1" -- sh -c '[ "$(cat /system/etc/security/cacerts/.trustanycert-system-owner 2>/dev/null)" = "trustanycert-v1" ] || mount --bind /data/adb/trustanycert-system-cacerts /system/etc/security/cacerts' 2>/dev/null
}

mount_apex_namespace /proc/1/ns/mnt && log "✓ Init (PID 1)"
if [ "$SYSTEM_COUNT" -ge 10 ]; then
    mount --bind "$SYSTEM_STAGE" "$SYSTEM_CACERTS" 2>/dev/null && log "✓ Global /system store"
    mount_system_namespace /proc/1/ns/mnt && log "✓ Init /system store"
fi

for zygote in zygote zygote64; do
    PID=$(pidof "$zygote" 2>/dev/null)
    if [ -n "$PID" ]; then
        mount_apex_namespace "/proc/$PID/ns/mnt" && log "✓ $zygote (PID $PID)"
        if [ "$SYSTEM_COUNT" -ge 10 ]; then mount_system_namespace "/proc/$PID/ns/mnt"; fi
    fi
done

# Settings app (for Trusted Credentials visibility)
SETTINGS_PID=$(pidof com.android.settings 2>/dev/null)
if [ -n "$SETTINGS_PID" ]; then
    mount_apex_namespace "/proc/$SETTINGS_PID/ns/mnt" && log "✓ Settings (PID $SETTINGS_PID)"
    if [ "$SYSTEM_COUNT" -ge 10 ]; then mount_system_namespace "/proc/$SETTINGS_PID/ns/mnt"; fi
fi

# Common HTTPS interception apps if running (best-effort)
for pkg in com.proxy.pin com.network.proxy com.network.proxy.flutter \
           tech.httptoolkit.android.v1 com.reqable.android \
           com.adguard.android com.google.android.gms com.android.chrome com.android.vending; do
    PID=$(pidof "$pkg" 2>/dev/null)
    if [ -n "$PID" ]; then
        mount_apex_namespace "/proc/$PID/ns/mnt" && log "✓ $pkg (PID $PID)"
        if [ "$SYSTEM_COUNT" -ge 10 ]; then mount_system_namespace "/proc/$PID/ns/mnt"; fi
    fi
done

sleep 1
MISSING=0
for CERT_FILE in "$CERT_DIR"/*.[0-9]*; do
    [ -f "$CERT_FILE" ] || continue
    NAME=$(basename "$CERT_FILE")
    if [ -f "$APEX_CACERTS/$NAME" ]; then
        log "✓ $NAME visible in APEX"
    else
        log "✗ $NAME not visible"
        MISSING=$((MISSING+1))
    fi
done
[ "$MISSING" -eq 0 ] && log "✓ SUCCESS: all certificates visible"

if [ "$SYSTEM_COUNT" -ge 10 ]; then
    for CERT_FILE in "$CERT_DIR"/*.[0-9]*; do
        [ -f "$CERT_FILE" ] || continue
        NAME=$(basename "$CERT_FILE")
        [ -f "$SYSTEM_CACERTS/$NAME" ] && log "✓ $NAME visible in /system store"
    done
fi

APEX_COUNT=$(ls -1 "$APEX_CACERTS"/*.[0-9]* 2>/dev/null | wc -l)
log "Total APEX certs: $APEX_COUNT"

log ""
# === Sync CA Certificates to Droidspaces containers & Termux/AGY ===
if [ -d /mnt/Droidspaces ]; then
    for cdir in /mnt/Droidspaces/*; do
        [ -d "$cdir/usr/local/share/ca-certificates" ] || continue
        cname=$(basename "$cdir")
        log "Syncing AdGuard certs to Droidspaces container: $cname"
        [ -f /data/misc/user/0/cacerts-added/0f4ed297.0 ] && openssl x509 -inform DER -in /data/misc/user/0/cacerts-added/0f4ed297.0 -out "$cdir/usr/local/share/ca-certificates/adguard_root.crt" 2>/dev/null
        [ -f /data/misc/user/0/cacerts-added/47ec1af8.0 ] && openssl x509 -inform DER -in /data/misc/user/0/cacerts-added/47ec1af8.0 -out "$cdir/usr/local/share/ca-certificates/adguard_intermediate.crt" 2>/dev/null
        chmod 644 "$cdir/usr/local/share/ca-certificates/adguard*.crt" 2>/dev/null
        chroot "$cdir" /usr/sbin/update-ca-certificates 2>/dev/null || /data/local/Droidspaces/bin/droidspaces -n "$cname" run -- update-ca-certificates 2>/dev/null
    done
fi

# Ensure DNS resolv.conf exists for Go/CLI tools (gh, git)
if [ -d /data/data/com.termux/files/usr/etc ]; then
    echo "nameserver 1.1.1.1" > /data/data/com.termux/files/usr/etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /data/data/com.termux/files/usr/etc/resolv.conf
    chmod 644 /data/data/com.termux/files/usr/etc/resolv.conf
    chcon u:object_r:system_file:s0 /data/data/com.termux/files/usr/etc/resolv.conf 2>/dev/null
fi
log "Service completed"
log "════════════════════════════════════════════════════"
