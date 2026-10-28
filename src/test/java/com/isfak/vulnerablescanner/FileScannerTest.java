package com.isfak.vulnerablescanner;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import static org.junit.jupiter.api.Assertions.*;

class FileScannerTest {

    @Test
    void cleanFileShouldReturnCleanStatus() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "notes.txt",
                "text/plain",
                "This is a normal text file with no sensitive information.".getBytes()
        );

        ScanResult result = FileScanner.scanFile(file);

        assertEquals(ScanResult.Status.CLEAN, result.getStatus());
        assertTrue(result.isClean());
        assertTrue(result.getFindings().isEmpty());
    }

    @Test
    void shouldDetectAwsAccessKey() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "config.txt",
                "text/plain",
                "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP".getBytes()
        );

        ScanResult result = FileScanner.scanFile(file);

        assertEquals(ScanResult.Status.WARNING, result.getStatus());

        assertTrue(
                result.getFindings()
                        .stream()
                        .anyMatch(finding ->
                                finding.contains("AWS Access Key ID"))
        );
    }

    @Test
    void shouldDetectGithubPersonalAccessToken() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "github.txt",
                "text/plain",
                "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".getBytes()
        );

        ScanResult result = FileScanner.scanFile(file);

        assertEquals(ScanResult.Status.WARNING, result.getStatus());

        assertTrue(
                result.getFindings()
                        .stream()
                        .anyMatch(finding ->
                                finding.contains("GitHub personal access token"))
        );
    }

    @Test
    void shouldDetectPrivateKey() {
        String content =
                "-----BEGIN RSA PRIVATE KEY-----\n"
                        + "fake-private-key-content\n"
                        + "-----END RSA PRIVATE KEY-----";

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "private.txt",
                "text/plain",
                content.getBytes()
        );

        ScanResult result = FileScanner.scanFile(file);

        assertEquals(ScanResult.Status.WARNING, result.getStatus());

        assertTrue(
                result.getFindings()
                        .stream()
                        .anyMatch(finding ->
                                finding.contains("Private key block"))
        );
    }

    @Test
    void shouldDetectHardcodedPassword() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "application.properties",
                "text/plain",
                "password=SuperSecretPassword123".getBytes()
        );

        ScanResult result = FileScanner.scanFile(file);

        assertEquals(ScanResult.Status.WARNING, result.getStatus());

        assertTrue(
                result.getFindings()
                        .stream()
                        .anyMatch(finding ->
                                finding.contains("Hardcoded password/secret"))
        );
    }

    @Test
    void sensitiveFilenameShouldGenerateWarning() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                ".env",
                "text/plain",
                "NORMAL_VALUE=test".getBytes()
        );

        ScanResult result = FileScanner.scanFile(file);

        assertEquals(ScanResult.Status.WARNING, result.getStatus());

        assertTrue(
                result.getFindings()
                        .stream()
                        .anyMatch(finding ->
                                finding.contains("sensitive file type"))
        );
    }

    @Test
    void emptyFileShouldReturnError() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "empty.txt",
                "text/plain",
                new byte[0]
        );

        ScanResult result = FileScanner.scanFile(file);

        assertEquals(ScanResult.Status.ERROR, result.getStatus());
        assertTrue(result.isError());
        assertEquals("No file provided.", result.getSummary());
    }

    @Test
    void shouldReportCorrectLineNumberForSecret() {
        String content =
                "normal line\n"
                        + "another normal line\n"
                        + "password=MySecretPassword123\n"
                        + "final line";

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "example.txt",
                "text/plain",
                content.getBytes()
        );

        ScanResult result = FileScanner.scanFile(file);

        assertEquals(ScanResult.Status.WARNING, result.getStatus());

        assertTrue(
                result.getFindings()
                        .stream()
                        .anyMatch(finding ->
                                finding.contains("line 3"))
        );
    }

    // -----------------------------------------------------------------------
    // Binary-detection tests
    // -----------------------------------------------------------------------

    @Test
    void binaryFileShouldNotBeClean() {
        // Build content with a NUL byte embedded in the first 8 KB.
        byte[] content = new byte[100];
        content[42] = 0x00; // NUL byte → binary signal

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "data.bin",
                "application/octet-stream",
                content
        );

        ScanResult result = FileScanner.scanFile(file);

        assertNotEquals(ScanResult.Status.CLEAN, result.getStatus(),
                "A binary file must not be labeled clean");
    }

    @Test
    void binaryFileWithEmbeddedFakeSecretShouldNotBeClean() {
        // Craft binary content whose text portion includes an AWS key pattern.
        // The scanner detects the binary nature and must NOT return CLEAN.
        byte[] prefix = "AKIAABCDEFGHIJKLMNOP".getBytes();
        byte[] content = new byte[prefix.length + 50];
        System.arraycopy(prefix, 0, content, 0, prefix.length);
        content[prefix.length + 10] = 0x00; // NUL byte makes it binary

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "payload.bin",
                "application/octet-stream",
                content
        );

        ScanResult result = FileScanner.scanFile(file);

        assertNotEquals(ScanResult.Status.CLEAN, result.getStatus(),
                "A binary file with an embedded fake secret must not be labeled clean");
        assertTrue(result.getFindings().stream()
                        .anyMatch(f -> f.toLowerCase().contains("binary")),
                "Finding should mention binary detection");
    }

    @Test
    void binaryDetectionShouldProduceWarningStatus() {
        byte[] content = new byte[]{0x00, 0x01, 0x02, 0x03};

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "raw.bin",
                "application/octet-stream",
                content
        );

        ScanResult result = FileScanner.scanFile(file);

        assertEquals(ScanResult.Status.WARNING, result.getStatus(),
                "Binary file should produce WARNING, not ERROR or CLEAN");
    }
}
