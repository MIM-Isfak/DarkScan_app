package com.isfak.vulnerablescanner;

import org.springframework.web.multipart.MultipartFile;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FileScanner {

    private static final long MAX_FILE_SIZE_BYTES = 10L * 1024 * 1024;
    private static final long MAX_CONTENT_SCAN_BYTES = 2L * 1024 * 1024;

    private static final String[] SENSITIVE_SUFFIXES = {
        ".env", ".git", "config.php", "id_rsa", ".pem", ".pfx", ".key"
    };

    private static final Pattern[] SECRET_PATTERNS = {
        Pattern.compile("AKIA[0-9A-Z]{16}"),
        Pattern.compile("(?i)aws_secret_access_key\\s*=\\s*['\"]?[A-Za-z0-9/+=]{20,}"),
        Pattern.compile("(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"]?[A-Za-z0-9_\\-]{16,}"),
        Pattern.compile("(?i)(secret|password|passwd|pwd)\\s*[:=]\\s*['\"]?[^\\s'\"]{6,}"),
        Pattern.compile("-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----"),
        Pattern.compile("(?i)bearer\\s+[A-Za-z0-9\\-_.]{20,}"),
        Pattern.compile("ghp_[A-Za-z0-9]{36}"),
        Pattern.compile("sk-[A-Za-z0-9]{20,}")
    };

    private static final String[] SECRET_LABELS = {
        "AWS Access Key ID",
        "AWS Secret Access Key",
        "Generic API key",
        "Hardcoded password/secret",
        "Private key block",
        "Bearer token",
        "GitHub personal access token",
        "Generic sk- style API key"
    };

    public static ScanResult scanFile(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return ScanResult.error("No file provided.");
        }

        String filename = file.getOriginalFilename();
        if (filename == null || filename.isBlank()) {
            filename = "(unnamed file)";
        }

        List<String> findings = new ArrayList<>();

        String lowerName = filename.toLowerCase();
        for (String suffix : SENSITIVE_SUFFIXES) {
            if (lowerName.endsWith(suffix)) {
                findings.add("Filename suggests a sensitive file type (matched: \"" + suffix + "\")");
                break;
            }
        }

        if (file.getSize() > MAX_FILE_SIZE_BYTES) {
            findings.add("File is larger than 10MB (" + (file.getSize() / (1024 * 1024)) + "MB)");
        }

        if (file.getSize() > 0 && file.getSize() <= MAX_CONTENT_SCAN_BYTES) {
            try {
                findings.addAll(scanContent(file));
            } catch (IOException e) {
                findings.add("Could not read file content: " + e.getMessage());
            }
        } else if (file.getSize() > MAX_CONTENT_SCAN_BYTES) {
            findings.add("File too large to content-scan (limit 2MB) — filename/size checks only.");
        }

        if (findings.isEmpty()) {
            return ScanResult.clean("No issues detected in \"" + filename + "\".");
        }
        return ScanResult.warning(filename, findings);
    }

    private static List<String> scanContent(MultipartFile file) throws IOException {
        List<String> findings = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8))) {
            int lineNumber = 0;
            String line;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                for (int i = 0; i < SECRET_PATTERNS.length; i++) {
                    Matcher matcher = SECRET_PATTERNS[i].matcher(line);
                    if (matcher.find()) {
                        findings.add(SECRET_LABELS[i] + " found on line " + lineNumber);
                    }
                }
            }
        }
        return findings;
    }
}
