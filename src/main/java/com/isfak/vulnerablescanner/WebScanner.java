package com.isfak.vulnerablescanner;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class WebScanner {

    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;

    public static ScanResult scanWebsite(String urlStr) {
        if (urlStr == null || urlStr.isBlank()) {
            return ScanResult.error("No URL provided.");
        }

        String normalized = urlStr.trim();
        if (!normalized.startsWith("http://") && !normalized.startsWith("https://")) {
            normalized = "https://" + normalized;
        }

        URL url;
        try {
            url = new URI(normalized).toURL();
        } catch (URISyntaxException | MalformedURLException | IllegalArgumentException e) {
            return ScanResult.error("Invalid URL: " + urlStr);
        }

        String host = url.getHost();
        if (host == null || host.isBlank()) {
            return ScanResult.error("No host found in URL.");
        }

        if (host.equalsIgnoreCase("localhost") || host.endsWith(".localhost")) {
            return ScanResult.error("SSRF protection: localhost is not allowed.");
        }

        InetAddress address;
        try {
            address = InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            return ScanResult.error("Could not resolve host: " + host);
        }

        if (address.isLoopbackAddress()) {
            return ScanResult.error("SSRF protection: loopback address not allowed.");
        }
        if (address.isLinkLocalAddress()) {
            return ScanResult.error("SSRF protection: link-local address not allowed.");
        }
        if (address.isSiteLocalAddress()) {
            return ScanResult.error("SSRF protection: private network address not allowed.");
        }

        List<String> findings = new ArrayList<>();

        if ("http".equalsIgnoreCase(url.getProtocol())) {
            findings.add("Site is served over plain HTTP — traffic is not encrypted.");
        }

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) url.openConnection();
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestMethod("GET");
            conn.connect();

            checkHeader(conn, "Content-Security-Policy", findings, "Missing Content-Security-Policy header.");
            checkHeader(conn, "X-Frame-Options", findings, "Missing X-Frame-Options header.");
            checkHeader(conn, "Strict-Transport-Security", findings, "Missing Strict-Transport-Security header (HSTS).");
            checkHeader(conn, "X-Content-Type-Options", findings, "Missing X-Content-Type-Options header.");

            String server = conn.getHeaderField("Server");
            if (server != null && !server.isBlank()) {
                findings.add("Server header exposes software info: \"" + server + "\"");
            }

        } catch (IOException e) {
            return ScanResult.error("Could not connect to " + urlStr + ": " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }

        if (findings.isEmpty()) {
            return ScanResult.clean("All checked security headers are present on " + url.getHost());
        }
        return ScanResult.warning(url.toString(), findings);
    }

    private static void checkHeader(HttpURLConnection conn, String header,
                                     List<String> findings, String message) {
        if (conn.getHeaderField(header) == null) {
            findings.add(message);
        }
    }
}
