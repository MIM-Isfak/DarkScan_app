package com.isfak.vulnerablescanner;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Component
public class ScanReportJsonBuilder {

    private final ObjectMapper objectMapper;
    private final String version;

    public ScanReportJsonBuilder(ObjectMapper objectMapper, @Value("${darkscan.version}") String version) {
        this.objectMapper = objectMapper;
        this.version = version;
    }

    public String build(ScanResult result, Instant timestamp, String scanMode, String target)
            throws JsonProcessingException {
        String json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(new Report(
                "DarkScan", version, timestamp.toString(), scanMode, target, result.getStatus(),
                result.getFindings().size(), result.getFindings()));
        // JSON Unicode escapes preserve values while preventing HTML/script parser breakouts.
        return json.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
                .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029");
    }

    private record Report(String toolName, String toolVersion, String scanTimestamp, String scanMode,
                          String target, ScanResult.Status overallStatus, int findingCount,
                          List<Finding> findings) {}
}
