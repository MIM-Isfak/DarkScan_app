package com.isfak.vulnerablescanner;

import org.apache.hc.client5.http.DnsResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class WebScannerTest {

    // Save the real resolver so we can restore it after each test.
    private DnsResolver originalResolver;

    @BeforeEach
    void saveResolver() {
        originalResolver = WebScanner.dnsResolver;
    }

    @AfterEach
    void restoreResolver() {
        WebScanner.dnsResolver = originalResolver;
    }

    // -----------------------------------------------------------------------
    // Helper: create a stub resolver that returns a single IP.
    // -----------------------------------------------------------------------

    private static DnsResolver stubResolver(String ip) {
        return hostname -> new InetAddress[]{InetAddress.getByAddress(
                hostname, parseIp(ip))};
    }

    /** Parse a dotted-quad string to a 4-byte array without DNS. */
    private static byte[] parseIp(String ip) throws UnknownHostException {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            throw new UnknownHostException("Not IPv4: " + ip);
        }
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            bytes[i] = (byte) Integer.parseInt(parts[i]);
        }
        return bytes;
    }

    // -----------------------------------------------------------------------
    // Existing tests (no network needed — these are rejected before connect)
    // -----------------------------------------------------------------------

    @Test
    void shouldRejectLongDotInputWithinOneSecond() {
        String input = "http://a" + ".".repeat(100_000) + "b/";

        ScanResult result = assertTimeoutPreemptively(Duration.ofSeconds(1),
                () -> WebScanner.scanWebsite(input));

        assertTrue(result.isError());
        assertEquals("Please enter a URL no longer than 2048 characters.", result.getSummary());
    }

    @Test
    void shouldRejectLongHostnameBeforeStrippingDots() {
        ScanResult result = WebScanner.scanWebsite("http://localhost" + ".".repeat(245));

        assertTrue(result.isError());
        assertEquals("Please enter a hostname no longer than 253 characters.", result.getSummary());
    }

    @Test
    void shouldStripTrailingDotsBeforeCheckingLocalhost() {
        ScanResult result = WebScanner.scanWebsite("http://LOCALHOST...");

        assertTrue(result.isError());
        assertEquals("SSRF protection: localhost is not allowed.", result.getSummary());
    }

    @Test
    void shouldRejectLocalhost() {
        ScanResult result = WebScanner.scanWebsite("http://localhost");

        assertEquals(ScanResult.Status.ERROR, result.getStatus());
        assertTrue(result.isError());
    }

    @Test
    void shouldRejectLoopbackIp() {
        ScanResult result = WebScanner.scanWebsite("http://127.0.0.1");

        assertEquals(ScanResult.Status.ERROR, result.getStatus());
        assertTrue(result.isError());
    }

    @Test
    void shouldRejectPrivateIpAddress() {
        ScanResult result = WebScanner.scanWebsite("http://192.168.1.10");

        assertEquals(ScanResult.Status.ERROR, result.getStatus());
        assertTrue(result.isError());
    }

    @Test
    void shouldRejectLinkLocalAddress() {
        ScanResult result = WebScanner.scanWebsite("http://169.254.169.254");

        assertEquals(ScanResult.Status.ERROR, result.getStatus());
        assertTrue(result.isError());
    }

    @Test
    void shouldRejectUnsupportedProtocol() {
        ScanResult result = WebScanner.scanWebsite("ftp://example.com");

        assertEquals(ScanResult.Status.ERROR, result.getStatus());
        assertTrue(result.isError());
    }

    @Test
    void shouldRejectUrlWithUserInfo() {
        ScanResult result = WebScanner.scanWebsite("http://user:password@example.com");

        assertEquals(ScanResult.Status.ERROR, result.getStatus());
        assertTrue(result.isError());
    }

    // -----------------------------------------------------------------------
    // Scheme normalization fix: ftp://x must be rejected, not rewritten.
    // -----------------------------------------------------------------------

    @Test
    void ftpSchemeShouldBeRejectedNotRewrittenToHttps() {
        ScanResult result = WebScanner.scanWebsite("ftp://example.com");

        assertTrue(result.isError(),
                "ftp:// must be rejected outright, not silently rewritten to https://ftp://example.com");
        assertTrue(result.getSummary().toLowerCase().contains("only http"),
                "Error should mention HTTP/HTTPS restriction");
    }

    @Test
    void fileSchemeShouldBeRejected() {
        ScanResult result = WebScanner.scanWebsite("file:///etc/passwd");

        assertTrue(result.isError(), "file:// must be rejected");
    }

    // -----------------------------------------------------------------------
    // Injected-resolver SSRF tests (no real network used).
    // -----------------------------------------------------------------------

    @Test
    void resolverReturningLoopbackShouldBeRejected() throws Exception {
        WebScanner.dnsResolver = stubResolver("127.0.0.1");

        ScanResult result = WebScanner.scanWebsite("http://legit-looking-host.example.com");

        assertTrue(result.isError(),
                "Host resolving to 127.0.0.1 must be rejected");
        assertTrue(result.getSummary().contains("SSRF protection"),
                "Error message should mention SSRF protection");
    }

    @Test
    void resolverReturningLinkLocalShouldBeRejected() throws Exception {
        WebScanner.dnsResolver = stubResolver("169.254.169.254");

        ScanResult result = WebScanner.scanWebsite("http://metadata.internal.example.com");

        assertTrue(result.isError(),
                "Host resolving to 169.254.169.254 (AWS metadata) must be rejected");
        assertTrue(result.getSummary().contains("SSRF protection"),
                "Error message should mention SSRF protection");
    }

    @Test
    void resolverReturningPrivate10xShouldBeRejected() throws Exception {
        WebScanner.dnsResolver = stubResolver("10.0.0.1");

        ScanResult result = WebScanner.scanWebsite("http://internal.corp.example.com");

        assertTrue(result.isError(),
                "Host resolving to 10.0.0.1 (private network) must be rejected");
        assertTrue(result.getSummary().contains("SSRF protection"),
                "Error message should mention SSRF protection");
    }

    @Test
    void resolverReturningPrivate192168ShouldBeRejected() throws Exception {
        WebScanner.dnsResolver = stubResolver("192.168.1.50");

        ScanResult result = WebScanner.scanWebsite("http://internal.example.com");

        assertTrue(result.isError(),
                "Host resolving to 192.168.1.50 must be rejected");
    }

    // -----------------------------------------------------------------------
    // getBlockedAddressReason unit tests (no network, no resolver).
    // -----------------------------------------------------------------------

    @Test
    void loopbackAddressIsBlocked() throws Exception {
        InetAddress addr = InetAddress.getByAddress("test", parseIp("127.0.0.1"));
        assertNotNull(WebScanner.getBlockedAddressReason(addr));
    }

    @Test
    void linkLocalAddressIsBlocked() throws Exception {
        InetAddress addr = InetAddress.getByAddress("test", parseIp("169.254.169.254"));
        assertNotNull(WebScanner.getBlockedAddressReason(addr));
    }

    @Test
    void privateClass10AddressIsBlocked() throws Exception {
        InetAddress addr = InetAddress.getByAddress("test", parseIp("10.0.0.1"));
        assertNotNull(WebScanner.getBlockedAddressReason(addr));
    }
}
