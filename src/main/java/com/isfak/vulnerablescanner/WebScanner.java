package com.isfak.vulnerablescanner;

import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.util.Timeout;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

public class WebScanner {

    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int READ_TIMEOUT_MS    = 5_000;
    private static final int OVERALL_TIMEOUT_MS = 10_000;

    /**
     * Known URL schemes that must be rejected (not prefixed with https://).
     * Any explicit scheme that is not http or https is rejected.
     */
    private static final String[] KNOWN_SCHEMES = {
        "ftp://", "ftps://", "sftp://", "file://", "gopher://",
        "ldap://", "ldaps://", "dict://", "smtp://", "telnet://",
        "irc://", "jar://", "mailto:", "data:", "javascript:"
    };

    // Package-private so tests can inject a stub resolver.
    static DnsResolver dnsResolver = SystemDefaultDnsResolver.INSTANCE;

    public static ScanResult scanWebsite(String urlStr) {

        if (urlStr == null || urlStr.isBlank()) {
            return ScanResult.error("No URL provided.");
        }

        if (urlStr.length() > 2048) {
            return ScanResult.error("Please enter a URL no longer than 2048 characters.");
        }

        String normalized = urlStr.trim();

        // Detect an explicit scheme BEFORE prepending https://.
        // If the user typed ftp://... or another non-http(s) scheme, reject it.
        String lowerNorm = normalized.toLowerCase(Locale.ROOT);
        for (String scheme : KNOWN_SCHEMES) {
            if (lowerNorm.startsWith(scheme)) {
                return ScanResult.error("Only HTTP and HTTPS URLs are allowed.");
            }
        }

        // Add HTTPS only when there is no explicit http:// or https:// prefix.
        if (!lowerNorm.startsWith("http://") && !lowerNorm.startsWith("https://")) {
            normalized = "https://" + normalized;
        }

        URI uri;
        try {
            uri = new URI(normalized);

            String scheme = uri.getScheme();
            if (scheme == null
                    || (!scheme.equalsIgnoreCase("http")
                    && !scheme.equalsIgnoreCase("https"))) {
                return ScanResult.error("Only HTTP and HTTPS URLs are allowed.");
            }

            // Prevent URLs such as: https://user:password@example.com
            if (uri.getUserInfo() != null) {
                return ScanResult.error("URLs containing user information are not allowed.");
            }

        } catch (URISyntaxException | IllegalArgumentException e) {
            return ScanResult.error("Invalid URL: " + urlStr);
        }

        String host;
        try {
            host = new java.net.URL(normalized).getHost();
        } catch (MalformedURLException e) {
            return ScanResult.error("Invalid URL: " + urlStr);
        }

        if (host == null || host.isBlank()) {
            return ScanResult.error("No host found in URL.");
        }

        if (host.length() > 253) {
            return ScanResult.error("Please enter a hostname no longer than 253 characters.");
        }

        // Normalize hostname (strip trailing dots).
        int hostEnd = host.length();
        while (hostEnd > 0 && host.charAt(hostEnd - 1) == '.') {
            hostEnd--;
        }
        String normalizedHost = host.substring(0, hostEnd).toLowerCase(Locale.ROOT);

        // Explicit localhost protection.
        if (normalizedHost.equals("localhost")
                || normalizedHost.endsWith(".localhost")
                || normalizedHost.equals("localhost.localdomain")) {
            return ScanResult.error("SSRF protection: localhost is not allowed.");
        }

        /*
         * Resolve ALL IP addresses for the hostname using the injected resolver.
         * Every resolved address must pass the SSRF checks.
         */
        InetAddress[] addresses;
        try {
            addresses = dnsResolver.resolve(normalizedHost);
        } catch (UnknownHostException e) {
            return ScanResult.error("Could not resolve host: " + normalizedHost);
        }

        if (addresses == null || addresses.length == 0) {
            return ScanResult.error("Could not resolve host: " + normalizedHost);
        }

        for (InetAddress address : addresses) {
            String blockReason = getBlockedAddressReason(address);
            if (blockReason != null) {
                return ScanResult.error("SSRF protection: " + blockReason + " is not allowed.");
            }
        }

        /*
         * Use the first validated IP to make the connection.
         * The original Host header and TLS SNI hostname remain unchanged
         * so that virtual hosting and certificate validation work correctly.
         */
        InetAddress targetAddress = addresses[0];
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);

        List<String> findings = new ArrayList<>();

        if ("http".equals(scheme)) {
            findings.add("Site is served over plain HTTP — traffic is not encrypted.");
        }

        int port = uri.getPort();
        if (port == -1) {
            port = "https".equals(scheme) ? 443 : 80;
        }

        /*
         * Build an HttpClient that:
         *  - uses a custom DnsResolver that always returns the already-validated IP
         *    (prevents a second DNS lookup / TOCTOU race)
         *  - keeps redirects disabled
         *  - applies connect + read + overall timeouts
         */
        DnsResolver lockedResolver = hostname -> new InetAddress[]{targetAddress};

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.of(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS))
                .setConnectTimeout(Timeout.of(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS))
                .setResponseTimeout(Timeout.of(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS))
                .build();

        try (CloseableHttpClient client = HttpClients.custom()
                .setConnectionManager(
                    PoolingHttpClientConnectionManagerBuilder.create()
                        .setDnsResolver(lockedResolver)
                        .setSSLSocketFactory(SSLConnectionSocketFactory.getSocketFactory())
                        .build()
                )
                .setDefaultRequestConfig(requestConfig)
                .disableRedirectHandling()
                .build()) {

            HttpHost target = new HttpHost(scheme, targetAddress.getHostAddress(), port);
            HttpGet request = new HttpGet(uri);
            // Ensure the Host header matches the original hostname (not the IP).
            request.setHeader("Host", normalizedHost + (uri.getPort() == -1 ? "" : ":" + uri.getPort()));
            request.setHeader("User-Agent", "DarkScan-Security-Scanner/1.0");

            long deadline = System.currentTimeMillis() + OVERALL_TIMEOUT_MS;

            try (ClassicHttpResponse response = client.executeOpen(target, request, null)) {

                if (System.currentTimeMillis() > deadline) {
                    return ScanResult.error("Request exceeded overall 10s deadline.");
                }

                checkResponseHeader(response, "Content-Security-Policy", findings,
                        "Missing Content-Security-Policy header.");
                checkResponseHeader(response, "X-Frame-Options", findings,
                        "Missing X-Frame-Options header.");

                if ("https".equals(scheme)) {
                    checkResponseHeader(response, "Strict-Transport-Security", findings,
                            "Missing Strict-Transport-Security header (HSTS).");
                }

                checkResponseHeader(response, "X-Content-Type-Options", findings,
                        "Missing X-Content-Type-Options header.");

                Header serverHeader = response.getFirstHeader("Server");
                if (serverHeader != null && !serverHeader.getValue().isBlank()) {
                    findings.add("Server header exposes software info: \"" + serverHeader.getValue() + "\"");
                }
            }

        } catch (IOException e) {
            return ScanResult.error("Could not connect to " + urlStr + ": " + e.getMessage());
        }

        if (findings.isEmpty()) {
            return ScanResult.clean("All checked security headers are present on " + normalizedHost);
        }

        return ScanResult.warning(normalized, findings);
    }

    /**
     * Returns a description if an address should be blocked from outbound scanning.
     * Returns null when the address is considered public.
     */
    static String getBlockedAddressReason(InetAddress address) {

        // 0.0.0.0 / ::
        if (address.isAnyLocalAddress()) {
            return "unspecified/local address";
        }

        // 127.0.0.0/8 / ::1
        if (address.isLoopbackAddress()) {
            return "loopback address";
        }

        // 169.254.0.0/16 and IPv6 link-local addresses
        if (address.isLinkLocalAddress()) {
            return "link-local address";
        }

        // IPv4 RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if (address.isSiteLocalAddress()) {
            return "private network address";
        }

        // Multicast
        if (address.isMulticastAddress()) {
            return "multicast address";
        }

        // IPv6 Unique Local Address: fc00::/7
        if (isIpv6UniqueLocal(address)) {
            return "IPv6 private network address";
        }

        // Carrier-grade NAT: 100.64.0.0/10
        if (isCarrierGradeNat(address)) {
            return "carrier-grade NAT address";
        }

        // Benchmark/testing: 198.18.0.0/15
        if (isBenchmarkAddress(address)) {
            return "non-public benchmark address";
        }

        return null;
    }

    /** Detect IPv6 Unique Local Addresses: fc00::/7 */
    private static boolean isIpv6UniqueLocal(InetAddress address) {
        if (!(address instanceof Inet6Address)) {
            return false;
        }
        byte[] bytes = address.getAddress();
        int firstByte = bytes[0] & 0xFF;
        return (firstByte & 0xFE) == 0xFC;
    }

    /** Detect IPv4 carrier-grade NAT: 100.64.0.0/10 */
    private static boolean isCarrierGradeNat(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length != 4) {
            return false;
        }
        int first  = bytes[0] & 0xFF;
        int second = bytes[1] & 0xFF;
        return first == 100 && second >= 64 && second <= 127;
    }

    /** Detect benchmark network: 198.18.0.0/15 */
    private static boolean isBenchmarkAddress(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length != 4) {
            return false;
        }
        int first  = bytes[0] & 0xFF;
        int second = bytes[1] & 0xFF;
        return first == 198 && (second == 18 || second == 19);
    }

    /** Check whether a security header exists in the response. */
    private static void checkResponseHeader(
            ClassicHttpResponse response,
            String headerName,
            List<String> findings,
            String message) {

        Header h = response.getFirstHeader(headerName);
        if (h == null || h.getValue().isBlank()) {
            findings.add(message);
        }
    }
}
