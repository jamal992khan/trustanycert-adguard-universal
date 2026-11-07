#!/system/bin/sh
# This script runs when user presses Action button in root manager
MODDIR=${0%/*}
LOG_FILE="/data/local/tmp/trustanycert.log"
CERT_DIR="$MODDIR/system/etc/security/cacerts"
OPENSSL=/data/data/com.termux/files/usr/bin/openssl
[ -x "$OPENSSL" ] || OPENSSL=openssl

detect_adguard_ca() {
    set -- "/data/user/0/com.adguard.android/certs/SSL/AdGuard Personal CA.cer" \
        "/data/data/com.adguard.android/certs/SSL/AdGuard Personal CA.cer"
    for candidate do
        [ -f "$candidate" ] || continue
        cert_info=$("$OPENSSL" x509 -in "$candidate" -noout -subject -subject_hash_old 2>/dev/null)
        if [ -z "$cert_info" ]; then
            cert_info=$("$OPENSSL" x509 -inform DER -in "$candidate" -noout -subject -subject_hash_old 2>/dev/null)
        fi
        subject=$(printf '%s\n' "$cert_info" | sed -n 's/^subject=//p')
        case "$subject" in
            *"AdGuard Personal CA"*) ;;
            *) continue ;;
        esac
        hash=$(printf '%s\n' "$cert_info" | tail -1)
        case "$hash" in
            ????????) ;;
            *) continue ;;
        esac
        case "$hash" in
            *[!0-9a-f]*) continue ;;
        esac
        cp -f "$candidate" "$CERT_DIR/$hash.0" || continue
        chown 0:0 "$CERT_DIR/$hash.0" 2>/dev/null
        chmod 0644 "$CERT_DIR/$hash.0"
        echo "- Refreshed AdGuard CA from its current app certificate: $hash.0"
        return 0
    done
    echo "- AdGuard CA file not found; keeping bundled module certificates"
    return 1
}

echo "╔════════════════════════════════════════╗"
echo "║  TrustAnyCert v1.0                     ║"
echo "║  Universal CA installer (WebUI)        ║"
echo "╚════════════════════════════════════════╝"
echo ""

API=$(getprop ro.build.version.sdk)
ANDROID_VERSION=$(getprop ro.build.version.release)
echo "- Android: $ANDROID_VERSION (API $API)"

detect_adguard_ca

echo "- Re-injecting module certificates now..."
FAST=1 sh "$MODDIR/service.sh"
INJECT_STATUS=$?
if [ "$INJECT_STATUS" -ne 0 ]; then
    echo "- Re-injection reported an error; see $LOG_FILE"
fi

CERT_COUNT=$(find "$CERT_DIR" -maxdepth 1 -type f -name "*.[0-9]*" 2>/dev/null | wc -l)
CERT_COUNT=$(echo "$CERT_COUNT" | tr -d ' ')

echo "- Certificates in module: $CERT_COUNT"

if [ "$CERT_COUNT" -eq 0 ] || [ -z "$CERT_COUNT" ]; then
    echo ""
    echo "-  No certificates installed yet."
    echo ""
    echo "   Open the module WebUI via your root manager"
    echo "   to upload a CA certificate (any format)."
    echo ""
    exit 0
fi

echo ""
echo "Certificates:"
find "$CERT_DIR" -maxdepth 1 -type f -name "*.[0-9]*" 2>/dev/null | while read cert; do
    name=$(basename "$cert")
    size=$(ls -la "$cert" | awk '{print $5}')
    subject=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/subject=//g' | head -1)
    echo "  - $name ($size bytes)"
    if [ -n "$subject" ]; then
        echo "    Subject: $(echo "$subject" | cut -c1-60)..."
    fi
done

echo ""
echo "System CA Store Status:"
find "$CERT_DIR" -maxdepth 1 -type f -name "*.[0-9]*" 2>/dev/null | while read cert; do
    name=$(basename "$cert")
    if [ -f "/system/etc/security/cacerts/$name" ]; then
        echo "  ✓ $name in /system/etc/security/cacerts"
    else
        echo "  ✗ $name NOT mounted (try rebooting)"
    fi
done

if [ "$API" -ge 34 ]; then
    echo ""
    echo "Android 14+ APEX Status:"
    APEX_DIR="/apex/com.android.conscrypt/cacerts"

    if [ -d "$APEX_DIR" ]; then
        find "$CERT_DIR" -maxdepth 1 -type f -name "*.[0-9]*" 2>/dev/null | while read cert; do
            name=$(basename "$cert")
            if [ -f "$APEX_DIR/$name" ]; then
                echo "  ✓ $name present in APEX"
            else
                echo "  ✗ $name NOT in APEX (needs re-injection or reboot)"
            fi
        done

        echo ""
        APEX_COUNT=$(find "$APEX_DIR" -maxdepth 1 -name "*.[0-9]*" -type f 2>/dev/null | wc -l)
        echo "  Total certs in APEX: $APEX_COUNT"
    else
        echo "  APEX CA directory not found"
    fi
else
    echo ""
    echo "Note: Standard Magic Mount is used for Android < 14"
fi

echo ""
echo "How to verify:"
echo "   Settings → Security → Encryption & credentials"
echo "   → Trusted credentials → System"
echo "   Look for your uploaded CA (listed above)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Options:"
echo "  1. Re-inject certificates (for Android 14+ APEX)"
echo "  2. View logs"
echo "  3. Exit"
echo ""
read -p "Select option [1-3]: " choice

case "$choice" in
    1)
        echo ""
        echo "Running certificate re-injection..."
        FAST=1 sh "$MODDIR/service.sh"
        echo ""
        echo "Done! Please check:"
        echo "  - Settings → Security → Trusted credentials → System"
        echo "  - Your interception tool should detect the certificate"
        ;;
    2)
        echo ""
        echo "=== Recent Logs ==="
        tail -50 "$LOG_FILE" 2>/dev/null || echo "No logs found"
        ;;
    3)
        echo "Goodbye!"
        ;;
    *)
        echo "Invalid option"
        ;;
esac

if [ "$KSU" = "true" ] || [ "$APATCH" = "true" ]; then
    echo ""
    echo "Dialog will close in 10 seconds..."
    sleep 10
fi
