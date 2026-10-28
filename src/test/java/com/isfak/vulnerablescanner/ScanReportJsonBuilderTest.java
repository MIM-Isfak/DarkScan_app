package com.isfak.vulnerablescanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ScanReportJsonBuilderTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final ScanReportJsonBuilder builder = new ScanReportJsonBuilder(mapper, "0.0.1-SNAPSHOT");
    private final Instant timestamp = Instant.parse("2026-10-29T12:34:56Z");

    @Test
    void exportsExactFieldsAndEveryFindingWithMetadata() throws Exception {
        List<Finding> findings = Arrays.stream(Finding.Type.values())
                .map(type -> new Finding("Finding " + type, type)).toList();
        JsonNode report = mapper.readTree(builder.build(ScanResult.warning("example.com", findings),
                timestamp, "website", "https://example.com"));

        assertEquals(Set.of("toolName", "toolVersion", "scanTimestamp", "scanMode", "target",
                "overallStatus", "findingCount", "findings"), fields(report));
        assertEquals("DarkScan", report.get("toolName").asText());
        assertEquals("0.0.1-SNAPSHOT", report.get("toolVersion").asText());
        assertEquals(timestamp, Instant.parse(report.get("scanTimestamp").asText()));
        assertEquals("website", report.get("scanMode").asText());
        assertEquals("https://example.com", report.get("target").asText());
        assertEquals("WARNING", report.get("overallStatus").asText());
        assertEquals(findings.size(), report.get("findingCount").asInt());
        assertEquals(findings.size(), report.get("findings").size());
        for (int i = 0; i < findings.size(); i++) {
            Finding finding = findings.get(i);
            JsonNode exported = report.get("findings").get(i);
            assertEquals(Set.of("message", "type", "severity", "fixTip", "explanation", "cweId",
                    "owaspCategory", "referenceUrl"), fields(exported));
            assertEquals(finding.getMessage(), exported.get("message").asText());
            assertEquals(finding.getType().name(), exported.get("type").asText());
            assertEquals(finding.getSeverity().name(), exported.get("severity").asText());
            assertEquals(finding.getFixTip(), exported.get("fixTip").asText());
            assertEquals(finding.getExplanation(), exported.get("explanation").asText());
            assertEquals(finding.getCweId(), exported.get("cweId").asText());
            assertEquals(finding.getOwaspCategory(), exported.get("owaspCategory").asText());
            assertEquals(finding.getReferenceUrl(), exported.get("referenceUrl").asText());
        }
    }

    @Test
    void exportsCleanAndErrorResultsWithTheirInputTarget() throws Exception {
        for (ScanResult result : List.of(ScanResult.clean("Clean"), ScanResult.error("Failed"))) {
            JsonNode report = mapper.readTree(builder.build(result, timestamp, "file", "notes.txt"));
            assertEquals("file", report.get("scanMode").asText());
            assertEquals("notes.txt", report.get("target").asText());
            assertEquals(result.getStatus().name(), report.get("overallStatus").asText());
            assertEquals(0, report.get("findingCount").asInt());
            assertTrue(report.get("findings").isArray());
            assertEquals(0, report.get("findings").size());
        }
    }

    @Test
    void hostileTextRoundTripsWithoutBreakingOutOfRenderedScript() throws Exception {
        String hostile = "\"quoted\" \\ newline\n</script><script>alert('x')</script>"
                + "</ScRiPt><!-- & < > \u2028\u2029 café";
        ScanResult result = ScanResult.warning(hostile,
                List.of(new Finding(hostile, Finding.Type.SERVER_DISCLOSURE)));
        String json = builder.build(result, timestamp, hostile, hostile);
        assertFalse(json.contains("<"));
        assertFalse(json.contains(">"));
        assertFalse(json.contains("&"));
        JsonNode report = mapper.readTree(json);
        assertEquals(hostile, report.get("target").asText());
        assertEquals(hostile, report.get("scanMode").asText());
        assertEquals(hostile, report.get("findings").get(0).get("message").asText());

        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setCharacterEncoding("UTF-8");
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(resolver);
        Context context = new Context();
        context.setVariable("result", result);
        context.setVariable("reportJson", json);
        String html = engine.process("result", context);
        String marker = "<script type=\"application/json\" id=\"scan-report\">";
        int start = html.indexOf(marker);
        assertTrue(start >= 0);
        String embedded = html.substring(start + marker.length(), html.indexOf("</script>", start));
        assertEquals(json, embedded);
        assertEquals(report, mapper.readTree(embedded));
        assertFalse(html.contains("<script>alert"));
        assertTrue(html.contains("Download JSON"));
    }

    private static Set<String> fields(JsonNode node) {
        Set<String> fields = new HashSet<>();
        node.fieldNames().forEachRemaining(fields::add);
        return fields;
    }
}
