package com.isfak.vulnerablescanner;

import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.MockedStatic;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class FindingMetadataTest {

    private static void assertMetadata(Finding finding, Severity severity, String cwe, String category) {
        assertEquals(severity, finding.getSeverity());
        assertEquals(cwe, finding.getCweId());
        assertEquals(category, finding.getOwaspCategory());
        assertFalse(finding.getExplanation().isBlank());
        assertFalse(finding.getFixTip().isBlank());
        assertFalse(finding.getFixTip().contains("\n"));
        assertEquals("https://owasp.org/Top10/2021/" + (category.startsWith("A02")
                ? "A02_2021-Cryptographic_Failures/" : category.startsWith("A07")
                ? "A07_2021-Identification_and_Authentication_Failures/" : "A05_2021-Security_Misconfiguration/"),
                finding.getReferenceUrl());
    }

    @ParameterizedTest
    @CsvSource({
        "AKIAABCDEFGHIJKLMNOP, AWS Access Key ID, LOW, CWE-200, A05:2021 Security Misconfiguration",
        "aws_secret_access_key=ABCDEFGHIJKLMNOPQRST, AWS Secret Access Key, HIGH, CWE-798, A07:2021 Identification and Authentication Failures",
        "api_key=ABCDEFGHIJKLMNOP, Generic API key, HIGH, CWE-798, A07:2021 Identification and Authentication Failures",
        "password=secret123, Hardcoded password/secret, HIGH, CWE-798, A07:2021 Identification and Authentication Failures",
        "-----BEGIN RSA PRIVATE KEY-----, Private key block, HIGH, CWE-321, A02:2021 Cryptographic Failures",
        "Bearer ABCDEFGHIJKLMNOPQRST, Bearer token, HIGH, CWE-798, A07:2021 Identification and Authentication Failures",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890, GitHub personal access token, HIGH, CWE-798, A07:2021 Identification and Authentication Failures",
        "sk-ABCDEFGHIJKLMNOPQRST, Generic sk- style API key, HIGH, CWE-798, A07:2021 Identification and Authentication Failures"
    })
    void secretPatternsRetainMessagesAndHaveMetadata(String content, String label, Severity severity,
                                                    String cwe, String category) {
        ScanResult result = FileScanner.scanFile(new MockMultipartFile("file", "notes.txt", "text/plain",
                ("normal line\n" + content).getBytes(StandardCharsets.UTF_8)));
        Finding finding = result.getFindings().stream()
                .filter(f -> f.getMessage().equals(label + " found on line 2")).findFirst().orElseThrow();
        assertMetadata(finding, severity, cwe, category);
    }

    @Test
    void sensitiveFilenameAndBinaryCoverageRemainSeparateFindings() {
        ScanResult result = FileScanner.scanFile(new MockMultipartFile("file", "private.pem", null,
                new byte[]{0, 1, 2}));
        assertEquals(2, result.getFindings().size());
        assertEquals("Filename suggests a sensitive file type (matched: \".pem\")",
                result.getFindings().get(0).getMessage());
        assertMetadata(result.getFindings().get(0), Severity.MEDIUM, "CWE-200", "A05:2021 Security Misconfiguration");
        assertEquals("Binary file detected — content scanning skipped (not a text file).",
                result.getFindings().get(1).getMessage());
        assertMetadata(result.getFindings().get(1), Severity.INFO, "CWE-693", "A05:2021 Security Misconfiguration");
    }

    @ParameterizedTest
    @CsvSource({"3, 1", "11, 2"})
    void oversizedFilesReportInformationalCoverageLimits(int megabytes, int count) throws Exception {
        MultipartFile file = mock(MultipartFile.class);
        when(file.getOriginalFilename()).thenReturn("large.txt");
        when(file.getSize()).thenReturn(megabytes * 1024L * 1024);
        ScanResult result = FileScanner.scanFile(file);
        assertEquals(count, result.getFindings().size());
        if (megabytes == 11) {
            assertEquals("File is larger than 10MB (11MB)", result.getFindings().get(0).getMessage());
        }
        assertEquals("File too large to content-scan (limit 2MB) — filename/size checks only.",
                result.getFindings().get(count - 1).getMessage());
        result.getFindings().forEach(f -> assertMetadata(f, Severity.INFO, "CWE-693",
                "A05:2021 Security Misconfiguration"));
        verify(file, never()).getInputStream();
    }

    @Test
    void unreadableFileReportsIncompleteScan() throws Exception {
        MultipartFile file = mock(MultipartFile.class);
        when(file.getOriginalFilename()).thenReturn("notes.txt");
        when(file.getSize()).thenReturn(10L);
        when(file.getInputStream()).thenThrow(new IOException("read failed"));
        Finding finding = FileScanner.scanFile(file).getFindings().get(0);
        assertEquals("Could not read file content: read failed", finding.getMessage());
        assertMetadata(finding, Severity.INFO, "CWE-693", "A05:2021 Security Misconfiguration");
    }

    @ParameterizedTest
    @CsvSource({"https, false", "https, true", "http, false", "http, true"})
    void webFindingsHaveMetadataWithoutChangingHeaderChecks(String scheme, boolean blank) throws Exception {
        try (BasicClassicHttpResponse response = new BasicClassicHttpResponse(200)) {
            if (blank) {
                for (String header : List.of("Content-Security-Policy", "X-Frame-Options",
                        "Strict-Transport-Security", "X-Content-Type-Options")) {
                    response.setHeader(header, " ");
                }
            }
            response.setHeader("Server", "Example/1.0");
            List<Finding> findings = scanResponse(scheme, response).getFindings();
            assertEquals(5, findings.size());
            assertWebFinding(findings, "Missing Content-Security-Policy header.", Severity.MEDIUM, "CWE-693", false);
            assertWebFinding(findings, "Missing X-Frame-Options header.", Severity.MEDIUM, "CWE-1021", false);
            assertWebFinding(findings, "Missing X-Content-Type-Options header.", Severity.LOW, "CWE-693", false);
            assertWebFinding(findings, "Server header exposes software info: \"Example/1.0\"", Severity.LOW, "CWE-497", false);
            if (scheme.equals("https")) {
                assertWebFinding(findings, "Missing Strict-Transport-Security header (HSTS).", Severity.MEDIUM, "CWE-319", true);
            } else {
                assertWebFinding(findings, "Site is served over plain HTTP — traffic is not encrypted.", Severity.HIGH, "CWE-319", true);
                assertTrue(findings.stream().noneMatch(f -> f.getMessage().contains("HSTS")));
            }
        }
    }

    @Test
    void presentHeadersAndBlankServerRemainClean() throws Exception {
        try (BasicClassicHttpResponse response = new BasicClassicHttpResponse(200)) {
            response.setHeader("Content-Security-Policy", "default-src 'self'");
            response.setHeader("X-Frame-Options", "DENY");
            response.setHeader("Strict-Transport-Security", "max-age=31536000");
            response.setHeader("X-Content-Type-Options", "nosniff");
            response.setHeader("Server", " ");
            assertTrue(scanResponse("https", response).isClean());
        }
    }

    private static void assertWebFinding(List<Finding> findings, String message, Severity severity,
                                         String cwe, boolean cryptographic) {
        Finding finding = findings.stream().filter(f -> f.getMessage().equals(message)).findFirst().orElseThrow();
        assertMetadata(finding, severity, cwe, cryptographic
                ? "A02:2021 Cryptographic Failures" : "A05:2021 Security Misconfiguration");
    }

    private static ScanResult scanResponse(String scheme, BasicClassicHttpResponse response) throws Exception {
        DnsResolver original = WebScanner.dnsResolver;
        try (MockedStatic<HttpClients> clients = mockStatic(HttpClients.class)) {
            DnsResolver resolver = mock(DnsResolver.class);
            when(resolver.resolve("example.com")).thenReturn(new InetAddress[]{
                    InetAddress.getByAddress(new byte[]{93, (byte) 184, (byte) 216, 34})});
            WebScanner.dnsResolver = resolver;
            HttpClientBuilder builder = mock(HttpClientBuilder.class, RETURNS_SELF);
            CloseableHttpClient client = mock(CloseableHttpClient.class);
            clients.when(HttpClients::custom).thenReturn(builder);
            when(builder.build()).thenReturn(client);
            when(client.executeOpen(any(), any(), isNull())).thenReturn(response);
            return WebScanner.scanWebsite(scheme + "://example.com");
        } finally {
            WebScanner.dnsResolver = original;
        }
    }

    @Test
    void resultsTemplateRendersEscapedMessageBadgeAndReferenceLinks() {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setCharacterEncoding("UTF-8");
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(resolver);
        Context context = new Context();
        context.setVariable("result", ScanResult.warning("test", List.of(
                new Finding("<script>alert(1)</script>", Finding.Type.MISSING_CSP))));
        String html = engine.process("result", context);
        assertTrue(html.contains("class=\"severity severity-MEDIUM\""));
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assertFalse(html.contains("<script>"));
        assertTrue(html.contains("<summary>Explain</summary>"));
        assertTrue(html.contains("https://cwe.mitre.org/data/definitions/693.html"));
        assertTrue(html.contains("https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration/"));
        assertTrue(html.contains("Deploy a tested Content-Security-Policy"));
        assertTrue(html.contains("This does not prove XSS"));
    }
}
