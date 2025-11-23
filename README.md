# Java Vulnerability Scanner Web App

A web-based vulnerability scanner built with Java Spring Boot, Thymeleaf, and Bootstrap. This tool scans uploaded files for sensitive information and checks websites for important security headers.

---

## 🚀 Features

- **File Scan**
  - Warns about sensitive filenames (.env, .git, config.php)
  - Alerts if file size exceeds 10MB
  - Scans contents for passwords, API keys, or secrets

- **Website Scan**
  - Checks for missing security headers:
    - Content-Security-Policy
    - X-Frame-Options
    - Strict-Transport-Security
    - X-Content-Type-Options
  - Warns if site does not use HTTPS

- **Modern UI**
  - Responsive design using Bootstrap
  - Simple, clean workflow

---

## 🛠 Technologies Used

- Java (17+)
- Spring Boot (MVC)
- Thymeleaf for web templates
- Bootstrap (or custom CSS for UI)

---

## ⚡ How to Run

1. **Clone the repository:**
- git clone https://github.com/MIM-Isfak/Java-Vulnerability-Scanner-app.git

2. **Navigate to the project folder:**
- cd Java-Vulnerability-Scanner-app

3. **Start the server:**
- ./mvnw spring-boot:run(for windows) or mvn

4. **Open your browser:**  
- (http://localhost:8080)

---

## 🎯 Learning Outcomes

- Built a full-stack Java web app from scratch
- Implemented file and network IO from user input
- Detected basic security vulnerabilities and secrets
- Designed user-friendly web UI for security tools

---

## 🏗️ Future Improvements

- Export scan results to file (CSV or text)
- Add more file scan rules and advanced regex
- Support for user authentication
- Show scan history per user
- Improved error handling

---

## 🙌 Acknowledgements

- [Spring Boot](https://spring.io/projects/spring-boot)
- [Bootstrap](https://getbootstrap.com/)
- [Thymeleaf](https://www.thymeleaf.org/)

---

