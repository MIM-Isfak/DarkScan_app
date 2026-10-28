package com.isfak.vulnerablescanner;

public final class Finding {

    // Heuristic priorities, not proof of exploitability or credential validity.
    public enum Type {
        SENSITIVE_FILE(Severity.MEDIUM, "CWE-200", Category.MISCONFIGURATION,
                "Keep sensitive files out of public downloads and repositories.",
                "The filename is commonly used for configuration or keys. If publicly exposed, an attacker could read secrets or system details. The name alone does not prove sensitive content or exposure; the references describe the potential risk."),
        AWS_ACCESS_KEY_ID(Severity.LOW, "CWE-200", Category.MISCONFIGURATION,
                "Check for an accompanying secret key and rotate the pair if exposed.",
                "This looks like an AWS access key identifier. It is not a secret and cannot authenticate on its own, but can help an attacker identify credentials to target. This is a potential information disclosure mapping, not proof of compromised access."),
        SECRET(Severity.HIGH, "CWE-798", Category.AUTHENTICATION,
                "Revoke exposed credentials and load replacements from a secret manager.",
                "The text matches a password, API key, or token pattern. If it is a real active credential and someone obtains the file, they could impersonate its owner and access data or services. Pattern matches can be examples or false positives; the hard-coded credential mapping needs review."),
        PRIVATE_KEY(Severity.HIGH, "CWE-321", Category.CRYPTOGRAPHIC,
                "Replace exposed private keys and keep replacements in protected key storage.",
                "A private key marker was found. If a usable key is exposed, an attacker may impersonate its owner or decrypt data, depending on how the key is used. A marker alone does not confirm a complete key; the hard-coded key reference is an approximate mapping."),
        OVERSIZED_FILE(Severity.INFO, "CWE-693", Category.MISCONFIGURATION,
                "Review the file with a scanner that supports its size.",
                "The file exceeds the 10MB size warning threshold. Size alone is not a vulnerability, but unreviewed content could hide secrets an attacker could use if exposed. The references are broad scan-coverage guidance, not a confirmed weakness."),
        BINARY_FILE(Severity.INFO, "CWE-693", Category.MISCONFIGURATION,
                "Use a binary-aware scanner or inspect safely extracted text.",
                "A NUL byte suggests binary content, so the text secret scan was skipped. Secrets could remain undetected and be extracted by someone who obtains the file. This is a scan limitation, not evidence of malicious content; the references are approximate coverage guidance."),
        CONTENT_TOO_LARGE(Severity.INFO, "CWE-693", Category.MISCONFIGURATION,
                "Scan the complete file with a tool that supports files over 2MB.",
                "Content scanning was skipped because the file exceeds 2MB. Filename and size checks cannot rule out secrets that an attacker could recover from an exposed file. This is a scan limitation; the references are approximate coverage guidance."),
        READ_FAILURE(Severity.INFO, "CWE-693", Category.MISCONFIGURATION,
                "Check that the file is readable and scan it again.",
                "The scanner could not read the file content, so its review is incomplete. Secrets might remain unnoticed and be used by someone who obtains the file. This is a scan limitation rather than a confirmed vulnerability; the references are approximate coverage guidance."),
        INSECURE_HTTP(Severity.HIGH, "CWE-319", Category.CRYPTOGRAPHIC,
                "Serve the site over HTTPS and redirect HTTP requests to HTTPS.",
                "This URL uses unencrypted HTTP. Someone on the network could read or modify traffic, including any passwords or session data sent over it. The risk depends on the data exchanged; this check does not inspect that data."),
        MISSING_CSP(Severity.MEDIUM, "CWE-693", Category.MISCONFIGURATION,
                "Deploy a tested Content-Security-Policy that restricts scripts and other resources.",
                "No Content-Security-Policy response header was found. CSP can limit which scripts run, reducing the impact of injected content. If another flaw permits injection, an attacker may have fewer barriers to running scripts. This does not prove XSS; CWE-693 is a broad protection mapping."),
        MISSING_FRAME_OPTIONS(Severity.MEDIUM, "CWE-1021", Category.MISCONFIGURATION,
                "Set CSP frame-ancestors and, where appropriate, X-Frame-Options.",
                "No X-Frame-Options response header was found. Without framing restrictions, an attacker could embed the page and trick users into clicking hidden controls (clickjacking). A CSP frame-ancestors directive may already protect the page; this check does not evaluate it."),
        MISSING_HSTS(Severity.MEDIUM, "CWE-319", Category.CRYPTOGRAPHIC,
                "Enable Strict-Transport-Security on HTTPS after confirming HTTPS works reliably.",
                "The HTTPS response lacks HSTS, which tells browsers to require HTTPS for future visits. An attacker on the network could exploit an HTTP visit to intercept or alter traffic. Preloading or a cached policy may already protect the browser; this mapping describes the potential cleartext risk."),
        MISSING_CONTENT_TYPE_OPTIONS(Severity.LOW, "CWE-693", Category.MISCONFIGURATION,
                "Send X-Content-Type-Options: nosniff with accurate Content-Type headers.",
                "No X-Content-Type-Options response header was found. Browsers may guess a resource's type in some contexts. If an attacker controls content that is served with an unsuitable type, it could be interpreted as executable content. Exploitability depends on context; CWE-693 is a broad protection mapping."),
        SERVER_DISCLOSURE(Severity.LOW, "CWE-497", Category.MISCONFIGURATION,
                "Remove or minimize the Server header and keep server software patched.",
                "The Server response header reveals software information. An attacker may use product or version details to choose targeted attacks. A generic header may reveal very little, and this finding does not establish that the software is vulnerable.");

        private final Severity severity;
        private final String cweId;
        private final Category category;
        private final String fixTip;
        private final String explanation;

        Type(Severity severity, String cweId, Category category, String fixTip, String explanation) {
            this.severity = severity;
            this.cweId = cweId;
            this.category = category;
            this.fixTip = fixTip;
            this.explanation = explanation;
        }
    }

    private enum Category {
        CRYPTOGRAPHIC("A02:2021 Cryptographic Failures", "A02_2021-Cryptographic_Failures"),
        MISCONFIGURATION("A05:2021 Security Misconfiguration", "A05_2021-Security_Misconfiguration"),
        AUTHENTICATION("A07:2021 Identification and Authentication Failures", "A07_2021-Identification_and_Authentication_Failures");

        private final String label;
        private final String path;

        Category(String label, String path) {
            this.label = label;
            this.path = path;
        }
    }

    private final String message;
    private final Type type;
    private final Severity severity;
    private final String fixTip;
    private final String explanation;
    private final String cweId;
    private final String owaspCategory;
    private final String referenceUrl;

    public Finding(String message, Type type) {
        this.message = message;
        this.type = type;
        this.severity = type.severity;
        this.fixTip = type.fixTip;
        this.explanation = type.explanation;
        this.cweId = type.cweId;
        this.owaspCategory = type.category.label;
        this.referenceUrl = "https://owasp.org/Top10/2021/" + type.category.path + "/";
    }

    public String getMessage() { return message; }
    public Type getType() { return type; }
    public Severity getSeverity() { return severity; }
    public String getFixTip() { return fixTip; }
    public String getExplanation() { return explanation; }
    public String getCweId() { return cweId; }
    public String getOwaspCategory() { return owaspCategory; }
    public String getReferenceUrl() { return referenceUrl; }
}
