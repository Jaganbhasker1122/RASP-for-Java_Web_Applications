# Runtime Application Self-Protection (RASP)

A lightweight RASP engine for Java web applications that demonstrates runtime security enforcement through request inspection and threat detection.

## Table of Contents

1. [Overview](#overview)
2. [Problem Statement](#problem-statement)
3. [What is RASP?](#what-is-rasp)
4. [Key Features](#key-features)
5. [Architecture](#architecture)
6. [Risk Scoring System](#risk-scoring-system)
7. [Quick Start](#quick-start)
8. [Demo and Testing](#demo-and-testing)
9. [Configuration](#configuration)
10. [Project Structure](#project-structure)
11. [Technology Stack](#technology-stack)
12. [Limitations](#limitations)
13. [Future Enhancements](#future-enhancements)
14. [Learning Outcomes](#learning-outcomes)
15. [Contributing](#contributing)
16. [Support](#support)

---

## Overview

This project is an educational implementation of Runtime Application Self-Protection (RASP) for Java web applications built on Spring Boot. It demonstrates how security controls can be enforced at the application runtime level by intercepting HTTP requests, analyzing payloads for malicious patterns, calculating risk scores, and blocking requests before they reach application logic.

The project serves as a learning resource for understanding RASP concepts, servlet filter architecture, threat detection patterns, and secure application design. It is suitable for academic study, interview preparation, and building foundational security engineering skills.

---

## Problem Statement

Traditional security approaches rely on external infrastructure like Web Application Firewalls (WAFs) and network-level protection. These solutions have limitations:

- **Infrastructure Dependency:** WAFs require external resources; if unavailable, application remains unprotected
- **Blind Spots:** Cannot access application context or internal data, leading to false positives/negatives
- **Latency:** Network-based filtering adds hop latency to every request
- **Single Point of Failure:** Misconfigured WAF rules can block legitimate traffic or miss attacks
- **Incomplete Coverage:** Cannot protect against attacks exploiting application-specific logic

**RASP addresses this by** operating inside the application runtime with direct access to request context, execution flow, and application state. This enables more informed security decisions with lower false positive rates.

---

## What is RASP?

RASP (Runtime Application Self-Protection) is a security technology that runs inside an application to monitor and protect it in real time. Unlike external firewalls, RASP can:

- Access the full request context and application state
- Make protection decisions based on application logic
- Provide detailed logging of security events
- Operate independently of external security infrastructure

### RASP vs WAF Comparison

| Aspect | WAF | RASP |
|--------|-----|------|
| **Location** | External (network/proxy) | Inside application runtime |
| **Request Context** | Limited (HTTP only) | Full access to request and application state |
| **Decision Making** | Pattern-based (generic rules) | Pattern + context-based (application-aware) |
| **Latency** | Added network hop | Minimal overhead (same process) |
| **False Positives** | Higher (no context) | Lower (application-aware) |
| **Deployment** | Central infrastructure | Embedded in application |
| **Dependency** | External service required | Self-contained |
| **Coverage** | HTTP/network attacks | HTTP + application logic attacks |

Both technologies are complementary and often used together in defense-in-depth strategies.

---

## Key Features

### Security Detection

- **SQL Injection Prevention:** Detects common SQL injection patterns including comment syntax, boolean operators, and union-based payloads
- **Cross-Site Scripting (XSS) Protection:** Identifies script tags, event handlers, and JavaScript protocol schemes
- **Path Traversal Protection:** Detects directory traversal attempts using patterns like `../`, `..\\`, and encoded variants
- **Payload Encoding Detection:** Recognizes URL-encoded, Base64-encoded, and hexadecimal encoded payloads
- **Anomaly Detection:** Flags unusual request characteristics that deviate from normal patterns

### Architecture and Design

- **Global Servlet Filter:** Intercepts all HTTP requests before they reach application controllers
- **Risk Scoring Engine:** Multi-signal approach that combines detection results into a cumulative risk score
- **Explainable Decisions:** Detailed logging showing which rules triggered and why a request was blocked
- **Configurable Thresholds:** Risk threshold can be adjusted for different security postures
- **Extensible Rules Engine:** Simple pattern-matching system allows adding custom detection rules

### Developer Experience

- **Demo UI:** Web-based interface to load predefined attack examples and analyze them
- **Detailed Logging:** Server-side console output showing detection reasoning
- **Quick Integration:** Configured as a Spring Boot servlet filter with minimal setup
- **Clear Separation:** Security logic separated from business logic for maintainability

---

## Architecture

### Request Flow

```
1. HTTP Request Arrives
   |
   v
2. RASP Servlet Filter Intercepts Request
   |
   v
3. Request Normalization
   - URL decode parameters
   - Extract query strings and form data
   - Standardize payload format
   |
   v
4. Rule-Based Detection Analysis
   - SQL Injection pattern matching
   - XSS pattern matching
   - Path Traversal checks
   - Encoding analysis
   - Anomaly detection
   |
   v
5. Risk Score Calculation
   - Sum scores from all triggered rules
   - Compare against threshold (default: 60)
   |
   v
6. Decision
   - Risk Score < 60: ALLOW request to proceed
   - Risk Score >= 60: BLOCK request, show forbidden page
   |
   v
7. Logging
   - Log all security events for audit trail
   - Include detection details and risk scores
```

### Component Overview

The detection pipeline consists of:

1. **Servlet Filter Layer:** Entry point that intercepts all requests
2. **Payload Extraction:** Normalizes and standardizes request payloads
3. **Detection Engines:** Multiple engines analyze payloads for specific attack patterns
4. **Scoring Engine:** Combines detection signals into a cumulative risk score
5. **Decision Engine:** Compares score against threshold and blocks or allows request
6. **Logging:** Records all security events for analysis

---

## Risk Scoring System

The engine uses a cumulative scoring approach where multiple detection signals add up to determine final risk:

| Attack Type | Points | Rationale |
|------------|--------|-----------|
| SQL Injection | +70 | Direct database impact; high severity |
| XSS Injection | +60 | User session hijacking; medium-high severity |
| Path Traversal | +50 | File system access; medium severity |
| Payload Encoding | +10 | Suspicious but not immediately dangerous |
| Anomaly Detection | +10 | Unusual patterns warrant caution |

**Default Threshold:** 60 points (requests scoring 60 or above are blocked)

**Example Score Calculation:**
- Request with SQL injection pattern: 70 points → BLOCKED
- Request with encoded SQL injection: 70 + 10 = 80 points → BLOCKED
- Request with unusual encoding: 10 points → ALLOWED
- Clean request: 0 points → ALLOWED

Scores are intentionally conservative to minimize false negatives (missing attacks) while keeping false positives low.

---

## Quick Start

### Prerequisites

- Java 11 or later
- Maven 3.6 or later
- Spring Boot 2.7 or later

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Jaganbhasker1122/RASP-for-Java_Web_Applications.git
cd rasp-engine
```

2. Build the project:
```bash
mvn clean package
```

3. Run the application:
```bash
mvn spring-boot:run
```

4. Open your browser and navigate to:
```
http://localhost:8080
```

### First Test

The demo interface includes preloaded attack examples:

1. Click "Load SQL Injection Example"
2. Click "Analyze"
3. Observe the RASP engine block the request
4. Check the server console for detailed detection logs

---

## Demo and Testing

### Included Attack Examples

The demo UI provides several predefined attack payloads:

**SQL Injection Example:**
```
/?username=admin' OR '1'='1
```
Pattern detected: SQL boolean operator `OR` with logic manipulation

**XSS Example:**
```
/?search=<script>alert('XSS')</script>
```
Pattern detected: Script tag injection attempt

**Path Traversal Example:**
```
/?file=../../../../etc/passwd
```
Pattern detected: Directory traversal sequence `../`

### Realistic Attack Detection Example

**Attack Scenario:**
A user submits a login form with a crafted payload instead of a username:

**Request:**
```
POST /login?username=admin' OR '1'='1&password=anything
```

**RASP Analysis Process:**

1. Extract payload: `admin' OR '1'='1`
2. Analyze for SQL patterns:
   - Contains single quote (common in SQL injection): +5 points
   - Contains OR operator: +30 points
   - Contains comment syntax or logic manipulation: +35 points
3. Check encoding: Payload is plain text (no encoding bonus): 0 points
4. Final score: 70 points
5. Decision: Score >= 60 → BLOCK

**Server Log Output:**
```
[RASP] ============================================
[RASP] SECURITY THREAT DETECTED
[RASP] ============================================
[RASP] Request URI: /login?username=admin' OR '1'='1
[RASP] Detected Attack Types: [SQL_INJECTION]
[RASP] Risk Score: 70
[RASP] Timestamp: 2024-01-15T10:30:45.123Z
[RASP] Status: BLOCKED
[RASP] ============================================
```

**User Experience:**
- User sees "403 Forbidden" error page
- Request never reaches application login controller
- Legitimate request with `username=john` passes through normally (score: 0)

### Manual Testing

Start the application and test with curl:

```bash
# Test SQL injection (should be blocked)
curl "http://localhost:8080/?username=admin' OR '1'='1"

# Test XSS (should be blocked)
curl "http://localhost:8080/?search=<script>alert('xss')</script>"

# Test path traversal (should be blocked)
curl "http://localhost:8080/?file=../../../../etc/passwd"

# Test normal request (should succeed)
curl "http://localhost:8080/?username=john&id=123"
```

### Run Unit Tests

```bash
# Run all tests
mvn test

# Run tests with coverage report
mvn test jacoco:report
```

---

## Configuration

### Application Settings

Edit `src/main/resources/application.yml` to customize RASP behavior:

```yaml
rasp:
  enabled: true
  risk-threshold: 60              # Requests with score >= 60 are blocked
  enable-logging: true            # Enable detailed security logging
  normalize-payloads: true        # URL decode and normalize payloads
  detection:
    sql-injection: true           # Enable SQL injection detection
    xss: true                     # Enable XSS detection
    path-traversal: true          # Enable path traversal detection
```

### Adding Custom Detection Rules

To add application-specific detection rules, extend the detection engine:

```java
public class CustomDetectionEngine extends BaseDetectionEngine {
    @Override
    public DetectionResult analyze(String payload) {
        // Your custom detection logic
        if (payload.contains("your_threat_pattern")) {
            return new DetectionResult("CUSTOM_THREAT", 50);
        }
        return DetectionResult.safe();
    }
}
```

---

## Project Structure

```
rasp-engine/
├── src/
│   ├── main/
│   │   ├── java/com/rasp/
│   │   │   ├── config/           # Spring configuration classes
│   │   │   ├── filter/           # Servlet filter implementation
│   │   │   ├── detection/        # Detection engine implementations
│   │   │   ├── scoring/          # Risk scoring logic
│   │   │   ├── controller/       # Web controllers (demo UI)
│   │   │   └── utils/            # Utility classes
│   │   └── resources/
│   │       ├── application.yml   # Configuration file
│   │       └── templates/
│   │           ├── index.html    # Demo home page
│   │           └── rasp-blocked.html  # Forbidden page
│   └── test/
│       └── java/                 # Unit tests
├── pom.xml                       # Maven dependencies
└── README.md                     # This file
```

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | Java 11+ | Core implementation |
| Framework | Spring Boot 2.7+ | Application framework and filter configuration |
| Security | Servlet Filter API | HTTP request interception and filtering |
| Frontend | HTML5, CSS3, JavaScript | Demo interface |
| Build Tool | Maven 3.6+ | Project compilation and dependency management |
| Testing | JUnit 5, Mockito | Unit testing framework |

---

## Limitations

This is an educational project demonstrating RASP concepts. The following limitations should be noted:

**Query Parameters Only:**
- Currently analyzes only URL query parameters
- POST body parameters, headers, and cookies are not analyzed (version 2.0 feature)
- JSON payload inspection is not included

**Detection Scope:**
- Pattern matching is rule-based and may not catch obfuscated or novel attacks
- No machine learning or behavioral analysis in version 1.0
- False positives possible for legitimate encoded data (e.g., mathematical formulas)

**Performance Considerations:**
- Designed for educational purposes; production deployment requires additional hardening
- No distributed caching or optimization for high-traffic scenarios
- Request filtering overhead approximately 1-2ms per request

**Response Filtering:**
- Only request inspection is implemented
- Response filtering or data exfiltration prevention is not included

**No Machine Learning:**
- Offline ML integration is planned but not implemented
- Detection relies entirely on pattern matching rules

---

## Future Enhancements

### Version 2.0 (Planned)
- POST body and JSON payload inspection
- HTTP header analysis and validation
- Cookie-based attack detection
- Enhanced logging with structured formats (JSON/CSV export)

### Version 3.0 (Planned)
- Offline machine learning training pipeline
- Advanced anomaly detection using statistical analysis
- Response filtering and data protection
- Distributed logging integration (ELK stack)

### Community Features (Long-term)
- Admin dashboard for rule management
- Security analytics and reporting
- Rate limiting and DDoS mitigation
- Webhook-based security event notifications

---

## Learning Outcomes

Working with this project helps you understand:

- **Runtime Security:** How security controls can be enforced at the application layer
- **Request Processing:** Servlet filter architecture and HTTP request lifecycle
- **Threat Detection:** Common web attack patterns and detection techniques
- **Risk Assessment:** Multi-signal scoring and decision-making logic
- **Secure Architecture:** Separation of concerns and extensible design
- **OWASP Top 10:** Practical protection against common web vulnerabilities
- **Spring Boot Security:** Security configuration and filter chains
- **Testing Security:** Testing threat detection and edge cases

This project is suitable for:
- Computer science students learning application security
- Cybersecurity role interviews (demonstrates practical security knowledge)
- Building foundational security engineering skills
- Understanding RASP as an alternative to WAF-only approaches

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a pull request with a clear description

### Development Setup

```bash
git clone https://github.com/Jaganbhasker1122/RASP-for-Java_Web_Applications.git
cd rasp-engine
mvn clean install
mvn spring-boot:run
```

### Code Guidelines

- Follow Google Java Style Guide
- Write meaningful variable and method names
- Add unit tests for new detection rules
- Document public methods and complex logic
- Keep changes focused and well-scoped

---

## Support

For questions or suggestions, contact:

- Email: jaganbhaskergurram@gmail.com

---

## References

- [OWASP Top 10 Web Application Security Risks](https://owasp.org/www-project-top-ten/)
- [OWASP RASP Standards](https://owasp.org/www-community/attacks/Runtime_Application_Self_Protection)
- [Spring Boot Security Documentation](https://docs.spring.io/spring-security/reference/)
- [Java Servlet API Documentation](https://tomcat.apache.org/tomcat-10.0-doc/servletapi/)
- [CWE Top 25 - Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)

---

**Author:** Gurram Jagan Bhasker

This project is provided for educational purposes to help understand runtime application security concepts and RASP architecture.
