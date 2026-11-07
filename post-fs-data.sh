#!/system/bin/sh
# Bootstrap APEX CA injection; runs early at boot before zygote.

MODDIR=${0%/*}
LOG_FILE="/data/local/tmp/trustanycert.log"
CERT_DIR="${MODDIR}/system/etc/security/cacerts"
TEMP_DIR="/data/local/tmp/trustanycert-apex-ca"
MOUNT_MARKER=".trustanycert-owner"
MOUNT_OWNER="trustanycert-v1"

mkdir -p /data/local/tmp 2>/dev/null
echo "" > "$LOG_FILE"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log "╔════════════════════════════════════════════════════╗"
log "║  TrustAnyCert v1.0 (AdGuard Compatible)           ║"
log "╚════════════════════════════════════════════════════╝"
log ""
log "Post-fs-data started"
log "Module: $MODDIR"

API=$(getprop ro.build.version.sdk)
ANDROID_VERSION=$(getprop ro.build.version.release)
log "Android: $ANDROID_VERSION (API $API)"

mkdir -p "$CERT_DIR"

# === AdGuard CA auto-sync (Root & Intermediate) ===
for HASH in "0f4ed297" "47ec1af8"; do
    FILE=$(ls /data/misc/user/*/cacerts-added/${HASH}.* 2>/dev/null | head -n 1)
    if [ -n "$FILE" ] && [ -f "$FILE" ]; then
        log "Found AdGuard cert: $(basename "$FILE") -> syncing to $CERT_DIR/${HASH}.0"
        cp -f "$FILE" "$CERT_DIR/${HASH}.0"
        rm -f /data/misc/user/*/cacerts-removed/${HASH}.* 2>/dev/null
        chown 0:0 "$CERT_DIR/${HASH}.0"
        chmod 0644 "$CERT_DIR/${HASH}.0"
        CERT_CONTEXT=$(ls -Zd "$CERT_DIR" 2>/dev/null | awk '{print $1}')
        if [ -n "$CERT_CONTEXT" ] && [ "$CERT_CONTEXT" != "?" ]; then
            chcon "$CERT_CONTEXT" "$CERT_DIR/${HASH}.0" 2>/dev/null
        fi
    fi
done
if [ "$KSU" = "true" ]; then
    log "Root: KernelSU/SukiSU (v$KSU_VER_CODE)"
elif [ "$APATCH" = "true" ]; then
    log "Root: APatch (v$APATCH_VER_CODE)"
else
    log "Root: Magisk/Other"
fi

mkdir -p "$CERT_DIR"
CERT_COUNT=$(find "$CERT_DIR" -maxdepth 1 -type f -name "*.[0-9]*" 2>/dev/null | wc -l)
CERT_COUNT=$(echo "$CERT_COUNT" | tr -d ' ')

if [ "$CERT_COUNT" = "0" ] || [ -z "$CERT_COUNT" ]; then
    log "No certificates uploaded yet. Use the WebUI to add one."
    log "Cert dir: $CERT_DIR"
    exit 0
fi

log "Found $CERT_COUNT certificate(s):"
find "$CERT_DIR" -maxdepth 1 -type f -name "*.[0-9]*" 2>/dev/null | while read c; do
    log "  - $(basename "$c")"
done

if [ "$API" -lt 34 ]; then
    log "Android < 14: Using Magic Mount"
    log "Done!"
    exit 0
fi

log "Android 14+ detected; attempting APEX injection before zygote startup"
FAST=1 sh "$MODDIR/service.sh"
INJECT_STATUS=$?
if [ "$INJECT_STATUS" -eq 0 ]; then
    log "Early APEX injection completed"
else
    log "Early APEX injection unavailable; service.sh will retry after boot"
fi
exit 0
