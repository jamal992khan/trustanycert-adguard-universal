/*
 * Pure-JS certificate parser + Android-compatible subject_hash computation.
 * Supports: PEM (CERTIFICATE, TRUSTED CERTIFICATE, X509 CERTIFICATE, PKCS7),
 *           DER (single X.509 cert),
 *           PKCS#7 SignedData (p7b / p7c, DER or PEM-wrapped).
 *
 * Android's TrustedCertificateStore looks up system CAs via filenames
 * of the form <subject_hash>.<N>. The hash used is OpenSSL's legacy
 * `subject_hash_old` (NativeCrypto.X509_NAME_hash_old in conscrypt),
 * which is:
 *   1. MD5 of the raw DER-encoded Subject Name bytes (no canonicalization)
 *   2. First 4 bytes interpreted as little-endian uint32
 *   3. Output as 8 lowercase hex chars
 *
 * We intentionally use the OLD algorithm (not the post-OpenSSL-1.0 canonical
 * SHA-1 one) because that's what Android accepts in its cert store.
 */
(function (global) {
    'use strict';

    // ---------- base64 ----------
    function b64Decode(b64) {
        const bin = atob(b64.replace(/\s+/g, ''));
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }
    function b64Encode(bytes) {
        let s = '';
        for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
        return btoa(s);
    }

    // ---------- hex ----------
    function toHex(bytes) {
        let s = '';
        for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
        return s;
    }

    // ---------- ASN.1 ----------
    function parseTLV(bytes, offset) {
        if (offset >= bytes.length) throw new Error('ASN.1: EOF');
        const tag = bytes[offset];
        let p = offset + 1;
        if (p >= bytes.length) throw new Error('ASN.1: EOF in length');
        let first = bytes[p++];
        let len;
        if ((first & 0x80) === 0) {
            len = first;
        } else {
            const n = first & 0x7f;
            if (n === 0) throw new Error('ASN.1: indefinite length unsupported');
            if (n > 4) throw new Error('ASN.1: length too large');
            len = 0;
            for (let i = 0; i < n; i++) {
                if (p >= bytes.length) throw new Error('ASN.1: EOF in length');
                len = (len * 256) + bytes[p++];
            }
        }
        const contentStart = p;
        const contentEnd = p + len;
        if (contentEnd > bytes.length) throw new Error('ASN.1: length overflow');
        return { tag, hdrLen: contentStart - offset, len, contentStart, contentEnd, totalEnd: contentEnd };
    }

    function encodeLength(len) {
        if (len < 128) return new Uint8Array([len]);
        const bytes = [];
        let n = len;
        while (n > 0) { bytes.unshift(n & 0xff); n = Math.floor(n / 256); }
        return new Uint8Array([0x80 | bytes.length].concat(bytes));
    }

    function encodeTLV(tag, content) {
        const L = encodeLength(content.length);
        const out = new Uint8Array(1 + L.length + content.length);
        out[0] = tag;
        out.set(L, 1);
        out.set(content, 1 + L.length);
        return out;
    }

    function concatBytes(arrs) {
        let total = 0;
        for (const a of arrs) total += a.length;
        const out = new Uint8Array(total);
        let p = 0;
        for (const a of arrs) { out.set(a, p); p += a.length; }
        return out;
    }

    // ---------- OID ----------
    function decodeOID(bytes) {
        if (bytes.length === 0) return '';
        const parts = [];
        const first = bytes[0];
        parts.push(Math.floor(first / 40));
        parts.push(first % 40);
        let val = 0;
        for (let i = 1; i < bytes.length; i++) {
            const b = bytes[i];
            val = (val * 128) + (b & 0x7f);
            if ((b & 0x80) === 0) {
                parts.push(val);
                val = 0;
            }
        }
        return parts.join('.');
    }
    function encodeOID(str) {
        const parts = str.split('.').map(x => parseInt(x, 10));
        const out = [parts[0] * 40 + parts[1]];
        for (let i = 2; i < parts.length; i++) {
            let v = parts[i];
            const tmp = [];
            do { tmp.push(v & 0x7f); v = Math.floor(v / 128); } while (v > 0);
            for (let j = tmp.length - 1; j >= 0; j--) {
                out.push(tmp[j] | (j > 0 ? 0x80 : 0));
            }
        }
        return new Uint8Array(out);
    }

    // ---------- String decoding ----------
    const TEXT_UTF8 = new TextDecoder('utf-8', { fatal: false });
    // latin1 is a forgiving fallback for byte-oriented strings
    const TEXT_LATIN1 = (function () {
        try { return new TextDecoder('iso-8859-1'); } catch (e) { return new TextDecoder('utf-8', { fatal: false }); }
    })();

    function decodeAsnString(bytes, tag) {
        switch (tag) {
            case 0x0c: // UTF8String
                return TEXT_UTF8.decode(bytes);
            case 0x13: // PrintableString
            case 0x16: // IA5String
            case 0x19: // VisibleString
            case 0x1a: // GeneralString
            case 0x12: // NumericString
            case 0x1b: // GraphicString
                // These are 7-bit ASCII in practice
                return TEXT_LATIN1.decode(bytes);
            case 0x14: // TeletexString (T61) - technically complex, latin1 is common
                return TEXT_LATIN1.decode(bytes);
            case 0x1e: { // BMPString (UCS-2 BE)
                let s = '';
                for (let i = 0; i + 1 < bytes.length; i += 2) {
                    s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
                }
                return s;
            }
            case 0x1c: { // UniversalString (UCS-4 BE)
                let s = '';
                for (let i = 0; i + 3 < bytes.length; i += 4) {
                    const cp = (bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3];
                    s += String.fromCodePoint(cp >>> 0);
                }
                return s;
            }
            default:
                return TEXT_UTF8.decode(bytes);
        }
    }

    // ---------- X.509 parse ----------
    // Returns offsets into the DER buffer (contentEnd-exclusive), so
    // we can reconstruct Name bytes exactly for canonicalization.
    function parseX509(der) {
        const cert = parseTLV(der, 0);
        if (cert.tag !== 0x30) throw new Error('Certificate: expected SEQUENCE');
        const tbs = parseTLV(der, cert.contentStart);
        if (tbs.tag !== 0x30) throw new Error('TBSCertificate: expected SEQUENCE');

        let p = tbs.contentStart;

        // [0] EXPLICIT Version (optional)
        if (der[p] === 0xa0) {
            const v = parseTLV(der, p);
            p = v.totalEnd;
        }
        // Serial
        p = parseTLV(der, p).totalEnd;
        // Signature algorithm
        p = parseTLV(der, p).totalEnd;
        // Issuer Name
        const issuerStart = p;
        const issuerTlv = parseTLV(der, p);
        p = issuerTlv.totalEnd;
        // Validity
        const validity = parseTLV(der, p);
        const nb = parseTLV(der, validity.contentStart);
        const na = parseTLV(der, nb.totalEnd);
        p = validity.totalEnd;
        // Subject Name
        const subjectStart = p;
        const subjectTlv = parseTLV(der, p);
        p = subjectTlv.totalEnd;

        return {
            subjectStart,
            subjectEnd: subjectTlv.totalEnd,
            issuerStart,
            issuerEnd: issuerTlv.totalEnd,
            notBefore: parseTime(der.slice(nb.contentStart, nb.contentEnd), nb.tag),
            notAfter: parseTime(der.slice(na.contentStart, na.contentEnd), na.tag),
        };
    }

    function parseTime(bytes, tag) {
        try {
            const s = TEXT_LATIN1.decode(bytes);
            const m = (tag === 0x17)
                ? s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$/) // UTCTime
                : s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$/); // GeneralizedTime
            if (!m) return null;
            let year = parseInt(m[1], 10);
            if (tag === 0x17) year = year >= 50 ? 1900 + year : 2000 + year;
            return new Date(Date.UTC(
                year, parseInt(m[2], 10) - 1, parseInt(m[3], 10),
                parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6], 10)
            ));
        } catch (e) { return null; }
    }

    // Parse a Name's RDNs
    function parseName(der, nameStart) {
        const seq = parseTLV(der, nameStart);
        if (seq.tag !== 0x30) throw new Error('Name: expected SEQUENCE');
        const rdns = [];
        let p = seq.contentStart;
        while (p < seq.contentEnd) {
            const set = parseTLV(der, p);
            if (set.tag !== 0x31) throw new Error('RDN: expected SET');
            const attrs = [];
            let ap = set.contentStart;
            while (ap < set.contentEnd) {
                const attr = parseTLV(der, ap);
                if (attr.tag !== 0x30) throw new Error('AttrTypeAndValue: expected SEQUENCE');
                const oidT = parseTLV(der, attr.contentStart);
                const valT = parseTLV(der, oidT.totalEnd);
                const oid = decodeOID(der.slice(oidT.contentStart, oidT.contentEnd));
                const value = decodeAsnString(der.slice(valT.contentStart, valT.contentEnd), valT.tag);
                const rawContent = der.slice(valT.contentStart, valT.contentEnd);
                attrs.push({ oid, tag: valT.tag, value, rawContent });
                ap = attr.totalEnd;
            }
            rdns.push(attrs);
            p = set.totalEnd;
        }
        return rdns;
    }

    // ---------- MD5 (pure JS) ----------
    // Web Crypto does not expose MD5, so we implement it here.
    // Used to compute Android's subject_hash_old over the raw subject DER.
    function md5(msg) {
        const m = new Uint8Array(msg);
        const ml = m.length;
        const bitLen = ml * 8;
        const padLen = ((ml + 9 + 63) & ~63);
        const buf = new Uint8Array(padLen);
        buf.set(m);
        buf[ml] = 0x80;
        const dv = new DataView(buf.buffer);
        // Length in bits, little-endian 64-bit
        dv.setUint32(padLen - 8, bitLen >>> 0, true);
        dv.setUint32(padLen - 4, Math.floor(bitLen / 0x100000000), true);

        const K = new Int32Array([
            -680876936, -389564586, 606105819, -1044525330, -176418897, 1200080426, -1473231341, -45705983,
            1770035416, -1958414417, -42063, -1990404162, 1804603682, -40341101, -1502002290, 1236535329,
            -165796510, -1069501632, 643717713, -373897302, -701558691, 38016083, -660478335, -405537848,
            568446438, -1019803690, -187363961, 1163531501, -1444681467, -51403784, 1735328473, -1926607734,
            -378558, -2022574463, 1839030562, -35309556, -1530992060, 1272893353, -155497632, -1094730640,
            681279174, -358537222, -722521979, 76029189, -640364487, -421815835, 530742520, -995338651,
            -198630844, 1126891415, -1416354905, -57434055, 1700485571, -1894986606, -1051523, -2054922799,
            1873313359, -30611744, -1560198380, 1309151649, -145523070, -1120210379, 718787259, -343485551,
        ]);
        const S = [
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
        ];
        function rol(x, n) { return (x << n) | (x >>> (32 - n)); }

        let a0 = 0x67452301 | 0, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476 | 0;
        const w = new Int32Array(16);
        for (let off = 0; off < padLen; off += 64) {
            for (let j = 0; j < 16; j++) w[j] = dv.getInt32(off + j * 4, true);
            let A = a0, B = b0, C = c0, D = d0;
            for (let i = 0; i < 64; i++) {
                let F, g;
                if (i < 16) { F = (B & C) | (~B & D); g = i; }
                else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
                else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
                else { F = C ^ (B | ~D); g = (7 * i) & 15; }
                const t = D;
                D = C;
                C = B;
                B = (B + rol((A + F + K[i] + w[g]) | 0, S[i])) | 0;
                A = t;
            }
            a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
        }
        const out = new Uint8Array(16);
        const odv = new DataView(out.buffer);
        odv.setInt32(0, a0, true);
        odv.setInt32(4, b0, true);
        odv.setInt32(8, c0, true);
        odv.setInt32(12, d0, true);
        return out;
    }

    // ---------- PKCS#7 extraction ----------
    function extractFromPKCS7(der) {
        // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
        const outer = parseTLV(der, 0);
        if (outer.tag !== 0x30) return [];
        const ct = parseTLV(der, outer.contentStart);
        if (ct.tag !== 0x06) return [];
        const oid = decodeOID(der.slice(ct.contentStart, ct.contentEnd));
        if (oid !== '1.2.840.113549.1.7.2') return [];
        const content0 = parseTLV(der, ct.totalEnd);
        if (content0.tag !== 0xa0) return [];
        const signedData = parseTLV(der, content0.contentStart);
        if (signedData.tag !== 0x30) return [];

        let p = signedData.contentStart;
        // Skip version, digestAlgorithms, encapContentInfo
        for (let i = 0; i < 3 && p < signedData.contentEnd; i++) {
            p = parseTLV(der, p).totalEnd;
        }
        // [0] IMPLICIT SET OF Certificate
        const certs = [];
        while (p < signedData.contentEnd) {
            const t = parseTLV(der, p);
            if (t.tag === 0xa0) {
                let cp = t.contentStart;
                while (cp < t.contentEnd) {
                    const c = parseTLV(der, cp);
                    if (c.tag === 0x30) {
                        certs.push(der.slice(cp, c.totalEnd));
                    }
                    cp = c.totalEnd;
                }
                break;
            }
            p = t.totalEnd;
        }
        return certs;
    }

    // Heuristic: is a SEQUENCE likely an X.509 cert vs PKCS#7 ContentInfo?
    // X.509 starts with SEQUENCE { SEQUENCE(TBSCertificate), ... }
    // PKCS#7 starts with SEQUENCE { OID(contentType), ... }
    function isPKCS7(der) {
        try {
            const outer = parseTLV(der, 0);
            if (outer.tag !== 0x30) return false;
            const first = parseTLV(der, outer.contentStart);
            return first.tag === 0x06;
        } catch (e) { return false; }
    }

    // ---------- PEM parsing ----------
    function parsePEM(text) {
        const out = [];
        const re = /-----BEGIN ([A-Z0-9 #]+?)-----([\s\S]*?)-----END \1-----/g;
        let m;
        while ((m = re.exec(text))) {
            const label = m[1].trim();
            if (!/CERTIFICATE|PKCS7|CMS|PKCS #7/i.test(label)) continue;
            try {
                const der = b64Decode(m[2]);
                out.push({ label, der });
            } catch (e) { /* skip bad block */ }
        }
        return out;
    }

    function derToPem(der) {
        const b64 = b64Encode(der);
        let pem = '-----BEGIN CERTIFICATE-----\n';
        for (let i = 0; i < b64.length; i += 64) pem += b64.slice(i, i + 64) + '\n';
        pem += '-----END CERTIFICATE-----\n';
        return pem;
    }

    // ---------- High-level API ----------
    function looksLikeText(bytes) {
        // Quick check: if the first 64 bytes are mostly printable ASCII, treat as text
        const n = Math.min(bytes.length, 64);
        let printable = 0;
        for (let i = 0; i < n; i++) {
            const b = bytes[i];
            if ((b >= 0x20 && b < 0x7f) || b === 0x09 || b === 0x0a || b === 0x0d) printable++;
        }
        return n > 0 && printable / n > 0.9;
    }

    async function parseCertificateFile(fileBytes) {
        // Returns: Array<{ der, pem, hash, subject, issuer, subjectCN, issuerCN, notBefore, notAfter, selfSigned }>
        let ders = [];
        let sourceFormat = 'unknown';

        if (looksLikeText(fileBytes)) {
            try {
                const text = TEXT_UTF8.decode(fileBytes);
                if (text.indexOf('-----BEGIN') !== -1) {
                    sourceFormat = 'pem';
                    const blocks = parsePEM(text);
                    if (!blocks.length) throw new Error('No valid PEM certificate blocks found');
                    for (const b of blocks) {
                        if (/PKCS ?7|CMS/i.test(b.label)) {
                            ders.push.apply(ders, extractFromPKCS7(b.der));
                        } else {
                            ders.push(b.der);
                        }
                    }
                }
            } catch (e) { /* fall through to DER parse */ }
        }

        if (ders.length === 0) {
            // Treat as DER - either single cert or PKCS#7
            if (fileBytes.length === 0 || fileBytes[0] !== 0x30) {
                throw new Error('Not a valid certificate (expected PEM or DER ASN.1)');
            }
            if (isPKCS7(fileBytes)) {
                sourceFormat = 'pkcs7-der';
                ders = extractFromPKCS7(fileBytes);
                if (!ders.length) throw new Error('PKCS#7 bundle contains no certificates');
            } else {
                sourceFormat = 'der';
                ders = [fileBytes];
            }
        }

        const results = [];
        for (const der of ders) {
            let info;
            try { info = parseX509(der); }
            catch (e) { throw new Error('Not a valid X.509 certificate: ' + e.message); }

            const subjectRdns = parseName(der, info.subjectStart);
            const issuerRdns = parseName(der, info.issuerStart);
            // Android uses subject_hash_old: MD5 of the raw DER subject bytes,
            // first 4 bytes interpreted as little-endian uint32.
            const subjectDer = der.slice(info.subjectStart, info.subjectEnd);
            const digest = md5(subjectDer);
            const hashVal = (digest[0] | (digest[1] << 8) | (digest[2] << 16) | (digest[3] << 24)) >>> 0;
            const hash = hashVal.toString(16).padStart(8, '0');

            const subject = formatName(subjectRdns);
            const issuer = formatName(issuerRdns);
            const selfSigned = bytesEqual(der.slice(info.subjectStart, info.subjectEnd),
                                           der.slice(info.issuerStart, info.issuerEnd));

            results.push({
                der,
                pem: derToPem(der),
                hash,
                sourceFormat,
                subject,
                issuer,
                subjectCN: extractCN(subjectRdns) || subject,
                issuerCN: extractCN(issuerRdns) || issuer,
                notBefore: info.notBefore,
                notAfter: info.notAfter,
                selfSigned,
            });
        }
        return results;
    }

    function bytesEqual(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
        return true;
    }

    const OID_NAMES = {
        '2.5.4.3': 'CN',
        '2.5.4.6': 'C',
        '2.5.4.7': 'L',
        '2.5.4.8': 'ST',
        '2.5.4.9': 'STREET',
        '2.5.4.10': 'O',
        '2.5.4.11': 'OU',
        '2.5.4.5': 'serialNumber',
        '1.2.840.113549.1.9.1': 'emailAddress',
        '0.9.2342.19200300.100.1.25': 'DC',
        '0.9.2342.19200300.100.1.1': 'UID',
    };

    function formatName(rdns) {
        const parts = [];
        for (const attrs of rdns) {
            const comps = [];
            for (const a of attrs) {
                const name = OID_NAMES[a.oid] || a.oid;
                comps.push(name + '=' + a.value);
            }
            parts.push(comps.join('+'));
        }
        return parts.join(', ');
    }

    function extractCN(rdns) {
        for (const attrs of rdns) {
            for (const a of attrs) {
                if (a.oid === '2.5.4.3') return a.value;
            }
        }
        return null;
    }

    // Export
    global.TrustAnyCert = {
        parseCertificateFile,
        b64Encode,
        b64Decode,
        toHex,
    };
})(typeof window !== 'undefined' ? window : globalThis);
