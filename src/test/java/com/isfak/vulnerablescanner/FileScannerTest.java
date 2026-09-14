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
}