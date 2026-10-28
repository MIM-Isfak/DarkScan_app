package com.isfak.vulnerablescanner;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.time.Instant;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class HomeController {

    private final ScanReportJsonBuilder reportJsonBuilder;

    public HomeController(ScanReportJsonBuilder reportJsonBuilder) {
        this.reportJsonBuilder = reportJsonBuilder;
    }

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @PostMapping("/scan")
    public String scan(@RequestParam("scanType") String scanType,
                        @RequestParam(value = "inputValue", required = false) String inputValue,
                        @RequestPart(value = "file", required = false) MultipartFile file,
                        Model model) throws JsonProcessingException {

        ScanResult result;

        if ("file".equals(scanType) && file != null && !file.isEmpty()) {
            result = FileScanner.scanFile(file);
        } else if ("website".equals(scanType) && inputValue != null && !inputValue.isBlank()) {
            result = WebScanner.scanWebsite(inputValue);
        } else {
            result = ScanResult.error("No valid input provided.");
        }

        model.addAttribute("result", result);
        model.addAttribute("reportJson", reportJsonBuilder.build(result, Instant.now(), scanType,
                "file".equals(scanType) ? (file == null ? null : file.getOriginalFilename()) : inputValue));
        return "result";
    }
}
