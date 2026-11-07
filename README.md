# TrustAnyCert (AdGuard Universal Edition)

Universal CA Certificate Installer module for **KernelSU**, **APatch**, and **Magisk** with full **AdGuard Root & Intermediate CA auto-sync**, **Android 14+ APEX Conscrypt bypass**, and **Droidspaces container support**.

---

## Key Features

1. **Complete AdGuard HTTPS Filtering Support**:
   - Automatically detects and syncs **both** the **AdGuard Root CA (`0f4ed297.0`)** and **AdGuard Intermediate CA (`47ec1af8.0`)** from the Android user store into the system certificate store at early boot (`post-fs-data`).
   - Prevents missing intermediate CA handshake errors in apps requiring full certificate chain validation.

2. **Android 14+ APEX Conscrypt Bypass**:
   - In modern Android (14/15/16+), Google moved the trusted CA store into the Conscrypt APEX package (`/apex/com.android.conscrypt/cacerts/`).
   - Uses multi-namespace injection (`nsenter`) to mount certificates across all critical process namespaces (PID 1, zygote64, webview_zygote, Chrome, Settings, Google Play Services).

3. **Droidspaces Container Auto-Sync**:
   - Droidspaces containers run in their own mount namespaces and do not read Android system CAs.
   - Automatically detects mounted Droidspaces containers (`/mnt/Droidspaces/*`), converts certificates to standard PEM format (`.crt`), and updates container stores (`/usr/local/share/ca-certificates/` + `update-ca-certificates`).
   - Fixes `apt update`, `curl`, `git`, `pip`, and `docker` SSL verification errors inside Droidspaces.

4. **Termux / CLI DNS Fix**:
   - Configures `/data/data/com.termux/files/usr/etc/resolv.conf` with proper SELinux permissions (`u:object_r:system_file:s0`) so Go-based CLI tools (`gh`, `git`, `docker`) never fail DNS lookups on Android.

5. **Built-in WebUI**:
   - Upload and manage custom certificates on the fly from your browser or KernelSU WebUI.

---

## Installation

1. Download the latest `TrustAnyCert-v1.1-AdGuard-Universal.zip` from [Releases](https://github.com/jamal992khan/trustanycert-adguard-universal/releases).
2. Open **KernelSU**, **APatch**, or **Magisk** app.
3. Go to **Modules** -> **Install from storage** -> select the ZIP.
4. Reboot your device.

---

## Handling Special Applications

| App Type | Behavior | Recommendation |
| :--- | :--- | :--- |
| **Chrome & WebViews** | Uses Android Conscrypt | **Works out-of-the-box** via APEX injection. |
| **Firefox** | Uses internal Mozilla NSS store | Settings -> About Firefox -> tap logo 5 times -> Secret Settings -> toggle **"Use third party CA certificates"**. |
| **Flutter / Hardcoded Pinning** | Bypasses Android CAs in native code | Use **LSPosed** with **TrustMeAlready** or exempt the app in AdGuard (*App Management -> Disable HTTPS filtering*). |

---

## Credits

- **[gorkemgun](https://github.com/gorkemgun/TrustAnyCert)** - Original TrustAnyCert creator
- **[AdGuard](https://adguard.com)** - Ad blocking and HTTPS filtering suite
