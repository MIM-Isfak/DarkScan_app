package com.isfak.vulnerablescanner;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @PostMapping("/scan")
    public String scan(@RequestParam("scanType") String scanType,
                        @RequestParam(value = "inputValue", required = false) String inputValue,
                        @RequestPart(value = "file", required = false) MultipartFile file,
                        Model model) {

        ScanResult result;

        if ("file".equals(scanType) && file != null && !file.isEmpty()) {
            result = FileScanner.scanFile(file);
        } else if ("website".equals(scanType) && inputValue != null && !inputValue.isBlank()) {
            result = WebScanner.scanWebsite(inputValue);
        } else {
            result = ScanResult.error("No valid input provided.");
        }

        model.addAttribute("result", result);
        return "result";
    }
}
