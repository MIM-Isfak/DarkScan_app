package com.isfak.vulnerablescanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class WebScannerTest {

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
}