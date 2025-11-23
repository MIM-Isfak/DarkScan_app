package com.isfak.vulnerablescanner;

import org.springframework.web.multipart.MultipartFile;

public class FileScanner {
    public static String scanFile(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return "No file provided!";
        }
        String filename = file.getOriginalFilename();
        if (filename.endsWith(".env") || filename.endsWith(".git") || filename.endsWith("config.php")) {
            return "Warning: Sensitive file detected (" + filename + ")";
        }
        if (file.getSize() > 1024 * 1024 * 10) { // >10MB
            return "Warning: Large file detected (" + filename + ")";
        }
        return "File scan completed. No issues detected: " + filename;
    }
}
