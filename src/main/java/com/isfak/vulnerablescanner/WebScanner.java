package com.isfak.vulnerablescanner;

import java.net.HttpURLConnection;
import java.net.URL;

public class WebScanner {
    public static String scanWebsite(String urlStr) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.connect();

            StringBuilder result = new StringBuilder();

            String csp = conn.getHeaderField("Content-Security-Policy");
            String xfo = conn.getHeaderField("X-Frame-Options");
            String hsts = conn.getHeaderField("Strict-Transport-Security");
            String xcto = conn.getHeaderField("X-Content-Type-Options");

            if (csp == null) result.append("Warning: Missing Content-Security-Policy header!<br>");
            if (xfo == null) result.append("Warning: Missing X-Frame-Options header!<br>");
            if (hsts == null) result.append("Warning: Missing Strict-Transport-Security header!<br>");
            if (xcto == null) result.append("Warning: Missing X-Content-Type-Options header!<br>");
            if (result.length() == 0) result.append("Website scan completed. All major security headers present.");

            return result.toString();
        } catch (Exception e) {
            return "Error scanning website: " + e.getMessage();
        }
    }
}
