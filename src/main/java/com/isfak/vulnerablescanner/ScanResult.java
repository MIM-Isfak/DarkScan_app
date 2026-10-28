package com.isfak.vulnerablescanner;

import java.util.Collections;
import java.util.List;

public class ScanResult {

    public enum Status { CLEAN, WARNING, ERROR }

    private final Status status;
    private final String subject;
    private final String summary;
    private final List<Finding> findings;

    private ScanResult(Status status, String subject, String summary, List<Finding> findings) {
        this.status = status;
        this.subject = subject;
        this.summary = summary;
        this.findings = findings;
    }

    public static ScanResult clean(String summary) {
        return new ScanResult(Status.CLEAN, null, summary, Collections.emptyList());
    }

    public static ScanResult warning(String subject, List<Finding> findings) {
        return new ScanResult(Status.WARNING, subject, findings.size() + " issue(s) found.", findings);
    }

    public static ScanResult error(String message) {
        return new ScanResult(Status.ERROR, null, message, Collections.emptyList());
    }

    public Status getStatus() { return status; }
    public String getSubject() { return subject; }
    public String getSummary() { return summary; }
    public List<Finding> getFindings() { return findings; }
    public boolean isClean() { return status == Status.CLEAN; }
    public boolean isError() { return status == Status.ERROR; }
}
