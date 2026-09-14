package com.isfak.vulnerablescanner;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class WebScanner {

    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;

    public static ScanResult scanWebsite(String urlStr) {

        if (urlStr == null || urlStr.isBlank()) {
            return ScanResult.error("No URL provided.");
        }

        String normalized = urlStr.trim();

        // Add HTTPS automatically when the user does not specify a protocol
        if (!normalized.startsWith("http://")
                && !normalized.startsWith("https://")) {
            normalized = "https://" + normalized;
        }

        URL url;

        try {
            URI uri = new URI(normalized);

            String scheme = uri.getScheme();

            if (scheme == null
                    || (!scheme.equalsIgnoreCase("http")
                    && !scheme.equalsIgnoreCase("https"))) {
                return ScanResult.error(
                        "Only HTTP and HTTPS URLs are allowed."
                );
            }

            // Prevent URLs such as:
            // https://user:password@example.com
            if (uri.getUserInfo() != null) {
                return ScanResult.error(
                        "URLs containing user information are not allowed."
                );
            }

            url = uri.toURL();

        } catch (URISyntaxException
                 | MalformedURLException
                 | IllegalArgumentException e) {

            return ScanResult.error(
                    "Invalid URL: " + urlStr
            );
        }

        String host = url.getHost();

        if (host == null || host.isBlank()) {
            return ScanResult.error(
                    "No host found in URL."
            );
        }

        // Normalize hostname
        String normalizedHost = host
                .toLowerCase(Locale.ROOT)
                .replaceAll("\\.+$", "");

        // Explicit localhost protection
        if (normalizedHost.equals("localhost")
                || normalizedHost.endsWith(".localhost")
                || normalizedHost.equals("localhost.localdomain")) {

            return ScanResult.error(
                    "SSRF protection: localhost is not allowed."
            );
        }

        /*
         * Resolve ALL IP addresses associated with the hostname.
         *
         * A hostname can resolve to multiple IPv4/IPv6 addresses.
         * Every resolved address must be considered safe before
         * allowing the request.
         */
        InetAddress[] addresses;

        try {

            addresses = InetAddress.getAllByName(normalizedHost);

        } catch (UnknownHostException e) {

            return ScanResult.error(
                    "Could not resolve host: " + normalizedHost
            );
        }

        if (addresses.length == 0) {

            return ScanResult.error(
                    "Could not resolve host: " + normalizedHost
            );
        }

        for (InetAddress address : addresses) {

            String blockReason = getBlockedAddressReason(address);

            if (blockReason != null) {

                return ScanResult.error(
                        "SSRF protection: "
                                + blockReason
                                + " is not allowed."
                );
            }
        }

        List<String> findings = new ArrayList<>();

        /*
         * HTTP traffic is unencrypted.
         */
        if ("http".equalsIgnoreCase(url.getProtocol())) {

            findings.add(
                    "Site is served over plain HTTP — traffic is not encrypted."
            );
        }

        HttpURLConnection conn = null;

        try {

            conn = (HttpURLConnection) url.openConnection();

            /*
             * Redirects are intentionally disabled.
             *
             * Otherwise a safe public URL could redirect the scanner
             * toward localhost or another internal address.
             */
            conn.setInstanceFollowRedirects(false);

            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);

            conn.setRequestMethod("GET");

            conn.setRequestProperty(
                    "User-Agent",
                    "DarkScan-Security-Scanner/1.0"
            );

            conn.connect();

            checkHeader(
                    conn,
                    "Content-Security-Policy",
                    findings,
                    "Missing Content-Security-Policy header."
            );

            checkHeader(
                    conn,
                    "X-Frame-Options",
                    findings,
                    "Missing X-Frame-Options header."
            );

            /*
             * HSTS only has security meaning over HTTPS.
             */
            if ("https".equalsIgnoreCase(url.getProtocol())) {

                checkHeader(
                        conn,
                        "Strict-Transport-Security",
                        findings,
                        "Missing Strict-Transport-Security header (HSTS)."
                );
            }

            checkHeader(
                    conn,
                    "X-Content-Type-Options",
                    findings,
                    "Missing X-Content-Type-Options header."
            );

            String server = conn.getHeaderField("Server");

            if (server != null && !server.isBlank()) {

                findings.add(
                        "Server header exposes software info: \""
                                + server
                                + "\""
                );
            }

        } catch (IOException e) {

            return ScanResult.error(
                    "Could not connect to "
                            + urlStr
                            + ": "
                            + e.getMessage()
            );

        } finally {

            if (conn != null) {
                conn.disconnect();
            }
        }

        if (findings.isEmpty()) {

            return ScanResult.clean(
                    "All checked security headers are present on "
                            + url.getHost()
            );
        }

        return ScanResult.warning(
                url.toString(),
                findings
        );
    }

    /**
     * Returns a description if an address should be blocked
     * from outbound scanning.
     *
     * Returns null when the address is considered public.
     */
    private static String getBlockedAddressReason(InetAddress address) {

        /*
         * 0.0.0.0 / ::
         */
        if (address.isAnyLocalAddress()) {
            return "unspecified/local address";
        }

        /*
         * 127.0.0.0/8 / ::1
         */
        if (address.isLoopbackAddress()) {
            return "loopback address";
        }

        /*
         * 169.254.0.0/16 and IPv6 link-local addresses
         */
        if (address.isLinkLocalAddress()) {
            return "link-local address";
        }

        /*
         * IPv4 RFC1918 private networks:
         *
         * 10.0.0.0/8
         * 172.16.0.0/12
         * 192.168.0.0/16
         */
        if (address.isSiteLocalAddress()) {
            return "private network address";
        }

        /*
         * Multicast networks should never be scanner targets.
         */
        if (address.isMulticastAddress()) {
            return "multicast address";
        }

        /*
         * IPv6 Unique Local Address range:
         *
         * fc00::/7
         *
         * InetAddress.isSiteLocalAddress() does not reliably
         * cover modern IPv6 ULA addresses.
         */
        if (isIpv6UniqueLocal(address)) {
            return "IPv6 private network address";
        }

        /*
         * Carrier-grade NAT:
         *
         * 100.64.0.0/10
         */
        if (isCarrierGradeNat(address)) {
            return "carrier-grade NAT address";
        }

        /*
         * Benchmark/testing network:
         *
         * 198.18.0.0/15
         */
        if (isBenchmarkAddress(address)) {
            return "non-public benchmark address";
        }

        return null;
    }

    /**
     * Detect IPv6 Unique Local Addresses:
     *
     * fc00::/7
     */
    private static boolean isIpv6UniqueLocal(InetAddress address) {

        if (!(address instanceof Inet6Address)) {
            return false;
        }

        byte[] bytes = address.getAddress();

        int firstByte = bytes[0] & 0xFF;

        return (firstByte & 0xFE) == 0xFC;
    }

    /**
     * Detect IPv4 carrier-grade NAT:
     *
     * 100.64.0.0/10
     */
    private static boolean isCarrierGradeNat(InetAddress address) {

        byte[] bytes = address.getAddress();

        if (bytes.length != 4) {
            return false;
        }

        int first = bytes[0] & 0xFF;
        int second = bytes[1] & 0xFF;

        return first == 100
                && second >= 64
                && second <= 127;
    }

    /**
     * Detect benchmark network:
     *
     * 198.18.0.0/15
     */
    private static boolean isBenchmarkAddress(InetAddress address) {

        byte[] bytes = address.getAddress();

        if (bytes.length != 4) {
            return false;
        }

        int first = bytes[0] & 0xFF;
        int second = bytes[1] & 0xFF;

        return first == 198
                && (second == 18 || second == 19);
    }

    /**
     * Check whether a security header exists.
     */
    private static void checkHeader(
            HttpURLConnection conn,
            String header,
            List<String> findings,
            String message) {

        String value = conn.getHeaderField(header);

        if (value == null || value.isBlank()) {
            findings.add(message);
        }
    }
}
