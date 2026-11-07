#!/system/bin/sh
# Unmount APEX bind and remove staging files when the module is uninstalled.

MODDIR=${0%/*}
LOG_FILE="/data/local/tmp/trustanycert.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [uninstall] $1" >> "$LOG_FILE"
}

log "Uninstall script started"

unmount_apex() {
    local apex_dir="/apex/com.android.conscrypt/cacerts"
    local system_dir="/system/etc/security/cacerts"
    local temp_dir="/data/adb/trustanycert-apex-cacerts"
    local system_stage="/data/adb/trustanycert-system-cacerts"
    local legacy_temp_dir="/data/local/tmp/trustanycert-apex-ca"
    local marker=".trustanycert-owner"
    local owner="trustanycert-v1"
    local count=0

    while { [ "$(cat "$apex_dir/$marker" 2>/dev/null)" = "$owner" ] || awk '$5=="/apex/com.android.conscrypt/cacerts" && ($4=="/local/tmp/trustanycert-apex-ca" || $4=="/adb/trustanycert-apex-cacerts") {found=1} END {exit !found}' /proc/self/mountinfo; } && [ "$count" -lt 16 ]; do
        umount -l "$apex_dir" 2>/dev/null || break
        count=$((count + 1))
    done

    count=0
    while { [ "$(cat "$system_dir/.trustanycert-system-owner" 2>/dev/null)" = "$owner" ] || awk '$5=="/system/etc/security/cacerts" && $4=="/adb/trustanycert-system-cacerts" {found=1} END {exit !found}' /proc/self/mountinfo; } && [ "$count" -lt 16 ]; do
        umount -l "$system_dir" 2>/dev/null || break
        count=$((count + 1))
    done

    for pid in 1 $(pidof zygote 2>/dev/null) $(pidof zygote64 2>/dev/null) \
               $(pidof webview_zygote 2>/dev/null) $(pidof com.android.settings 2>/dev/null) \
               $(pidof com.google.android.gms 2>/dev/null) $(pidof com.android.chrome 2>/dev/null) \
               $(pidof com.android.vending 2>/dev/null) $(pidof com.proxy.pin 2>/dev/null) \
               $(pidof com.network.proxy 2>/dev/null) $(pidof com.network.proxy.flutter 2>/dev/null) \
               $(pidof tech.httptoolkit.android.v1 2>/dev/null) $(pidof com.reqable.android 2>/dev/null); do
        if [ -d "/proc/$pid/ns/mnt" ]; then
            nsenter --mount="/proc/$pid/ns/mnt" -- sh -c 'count=0; while { [ "$(cat /apex/com.android.conscrypt/cacerts/.trustanycert-owner 2>/dev/null)" = "trustanycert-v1" ] || awk "\$5==\"/apex/com.android.conscrypt/cacerts\" && (\$4==\"/local/tmp/trustanycert-apex-ca\" || \$4==\"/adb/trustanycert-apex-cacerts\") {found=1} END {exit !found}" /proc/self/mountinfo; } && [ "$count" -lt 16 ]; do umount -l /apex/com.android.conscrypt/cacerts 2>/dev/null || break; count=$((count + 1)); done' 2>/dev/null
            nsenter --mount="/proc/$pid/ns/mnt" -- sh -c 'count=0; while { [ "$(cat /system/etc/security/cacerts/.trustanycert-system-owner 2>/dev/null)" = "trustanycert-v1" ] || awk "\$5==\"/system/etc/security/cacerts\" && \$4==\"/adb/trustanycert-system-cacerts\" {found=1} END {exit !found}" /proc/self/mountinfo; } && [ "$count" -lt 16 ]; do umount -l /system/etc/security/cacerts 2>/dev/null || break; count=$((count + 1)); done' 2>/dev/null
        fi
    done

    count=0
    while [ "$(cat "$legacy_temp_dir/$marker" 2>/dev/null)" = "$owner" ] && [ "$count" -lt 16 ]; do
        umount -l "$legacy_temp_dir" 2>/dev/null || break
        count=$((count + 1))
    done

    if [ "$(cat "$temp_dir/$marker" 2>/dev/null)" = "$owner" ]; then
        rm -rf "$temp_dir" 2>/dev/null
    fi
    if [ "$(cat "$system_stage/.trustanycert-system-owner" 2>/dev/null)" = "$owner" ]; then
        rm -rf "$system_stage" 2>/dev/null
    fi
    log "Detached TrustAnyCert APEX mounts"
}

cleanup_temp() {
    rm -f "$MODDIR/.apex_bypass_needed" 2>/dev/null
    log "Cleaned up temporary files"
}

unmount_apex
cleanup_temp

log "Uninstall completed"
log "APEX mounts detached; restart affected apps to refresh their trust view"
