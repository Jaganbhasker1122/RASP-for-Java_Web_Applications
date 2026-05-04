# Runtime Application Self-Protection (RASP)

A lightweight RASP engine for Java web applications that demonstrates runtime security enforcement through request inspection, threat detection, and ML-powered payload classification.

## Table of Contents

1. [Overview](#overview)
2. [Problem Statement](#problem-statement)
3. [What is RASP?](#what-is-rasp)
4. [Key Features](#key-features)
5. [Architecture](#architecture)
6. [Risk Scoring System](#risk-scoring-system)
7. [ML Integration](#ml-integration)
8. [Quick Start](#quick-start)
9. [Demo and Testing](#demo-and-testing)
10. [Configuration](#configuration)
11. [Project Structure](#project-structure)
12. [Technology Stack](#technology-stack)
13. [Limitations](#limitations)
14. [Future Enhancements](#future-enhancements)
15. [Learning Outcomes](#learning-outcomes)
16. [Contributing](#contributing)
17. [Support](#support)

---

## Overview

This project is an educational implementation of Runtime Application Self-Protection (RASP) for Java web applications built on Spring Boot. It demonstrates how security controls can be enforced at the application runtime level by intercepting HTTP requests, analyzing payloads for malicious patterns, calculating risk scores, and blocking requests before they reach application logic.

**Version 2.0** enhances the original rule-based engine with a Python-powered machine learning microservice that classifies payloads using a trained Logistic Regression model. The ML service runs alongside the Java application and provides probability-based threat scores as an additional signal in the decision pipeline.

The project serves as a learning resource for understanding RASP concepts, servlet filter architecture, threat detection patterns, ML-assisted security decisions, and secure application design. It is suitable for academic study, interview preparation, and building foundational security engineering skills.

---

## Problem Statement

Traditional security approaches rely on external infrastructure like Web Application Firewalls (WAFs) and network-level protection. These solutions have limitations:

- **Infrastructure Dependency:** WAFs require external resources; if unavailable, application remains unprotected
- **Blind Spots:** Cannot access application context or internal data, leading to false positives/negatives
- **Latency:** Network-based filtering adds hop latency to every request
- **Single Point of Failure:** Misconfigured WAF rules can block legitimate traffic or miss attacks
- **Incomplete Coverage:** Cannot protect against attacks exploiting application-specific logic
- **Static Rules:** Pure pattern-matching fails against obfuscated or novel attack variants

**RASP with ML addresses this by** operating inside the application runtime with direct access to request context, while using a trained model to score payloads that evade simple regex rules.

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
- **ML-Powered Classification:** A Logistic Regression model scores payloads based on extracted features and returns an attack probability

### Architecture and Design

- **Global Servlet Filter:** Intercepts all HTTP requests before they reach application controllers
- **Risk Scoring Engine:** Multi-signal approach that combines rule-based detection and ML predictions into a cumulative risk score
- **ML Microservice:** Lightweight Flask API that handles feature extraction and model inference independently
- **Explainable Decisions:** Detailed logging showing which rules triggered, ML probability, and why a request was blocked
- **Configurable Thresholds:** Risk threshold can be adjusted for different security postures
- **Extensible Rules Engine:** Simple pattern-matching system allows adding custom detection rules

### Developer Experience

- **Demo UI:** Web-based interface to load predefined attack examples and analyze them
- **Detailed Logging:** Server-side console output showing detection reasoning and ML scores
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
5. ML Microservice Call (Flask / Python)
   - Extract features: length, special_char_count,
     has_sql_keywords, has_script_tags, encoding_flag
   - Run Logistic Regression model
   - Return attack probability + prediction label
   |
   v
6. Risk Score Calculation
   - Sum scores from all triggered rules
   - Incorporate ML probability as additional signal
   - Compare against threshold (default: 60)
   |
   v
7. Decision
   - Risk Score < 60: ALLOW request to proceed
   - Risk Score >= 60: BLOCK request, show forbidden page
   |
   v
8. Logging
   - Log all security events for audit trail
   - Include detection details, ML output, and risk scores
```

### Component Overview

The detection pipeline consists of:

1. **Servlet Filter Layer:** Entry point that intercepts all requests
2. **Payload Extraction:** Normalizes and standardizes request payloads
3. **Detection Engines:** Multiple engines analyze payloads for specific attack patterns
4. **ML Microservice:** Flask API that extracts features and returns a classification probability
5. **Scoring Engine:** Combines rule-based and ML signals into a cumulative risk score
6. **Decision Engine:** Compares score against threshold and blocks or allows request
7. **Logging:** Records all security events for analysis

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
| ML High Probability (≥ 0.8) | +30 | Model strongly predicts attack |
| ML Medium Probability (0.5–0.8) | +15 | Model suggests elevated risk |

**Default Threshold:** 60 points (requests scoring 60 or above are blocked)

**Example Score Calculation:**
- Request with SQL injection pattern: 70 points → BLOCKED
- Request with encoded SQL injection: 70 + 10 = 80 points → BLOCKED
- Request flagged by ML only (probability 0.85): 30 points → ALLOWED (below threshold; rule-based clean)
- Request with unusual encoding + ML medium: 10 + 15 = 25 points → ALLOWED
- Clean request: 0 points → ALLOWED

Scores are intentionally conservative to minimize false negatives (missing attacks) while keeping false positives low.

---

## ML Integration

### Overview

Version 2.0 introduces a Python-based ML microservice that runs as a sidecar service alongside the Java application. The RASP filter calls this service for each request and uses the returned probability as an additional signal in the scoring engine.

### ML Service Stack

| Component | Technology |
|-----------|-----------|
| Framework | Flask + Flask-CORS |
| Model | Logistic Regression (scikit-learn) |
| Serving | Waitress (production) / Flask dev server |
| Feature Extraction | Python (regex + urllib) |
| Dataset | Labeled payload CSV (78 samples) |

### Feature Engineering

The ML service extracts the following features from each raw payload:

| Feature | Description |
|---------|-------------|
| `length` | Total character length of the payload |
| `special_char_count` | Count of non-alphanumeric, non-space characters |
| `has_sql_keywords` | 1 if payload contains SQL keywords (`select`, `union`, `drop`, etc.) |
| `has_script_tags` | 1 if payload contains XSS indicators (`<script>`, `eval(`, `onerror=`, etc.) |
| `encoding_flag` | 1 if URL-decoded payload differs from original (encoded content detected) |

### Training the Model

The model is trained using `train.py` against `dataset.csv`:

```bash
cd ml-service/
pip install -r requirements.txt
python train.py
```

Training output:
```
Loading dataset...
Splitting dataset...
Training Logistic Regression Model...
Model trained successfully. Test Accuracy: XX.XX%
Model saved to model.pkl
```

The trained model is serialized to `model.pkl` and loaded by the Flask service at startup.

### Running the ML Service

```bash
cd ml-service/
python app.py
```

The service starts on `http://0.0.0.0:5000`. The Java RASP filter is configured to call `http://localhost:5000/predict`.

### API Contract

**Endpoint:** `POST /predict`

**Request:**
```json
{
  "payload": "admin' OR '1'='1"
}
```

**Response:**
```json
{
  "probability": 0.94,
  "prediction": "attack",
  "features": {
    "length": 16,
    "special_char_count": 4,
    "has_sql_keywords": 1,
    "has_script_tags": 0,
    "encoding_flag": 0
  }
}
```

### ML Service Dependencies

```
flask
flask-cors
pandas
scikit-learn
Waitress
```

### Dataset

The model is trained on `dataset.csv`, which contains 78 labeled payloads covering SQL injection, XSS, path traversal, command injection, encoded attacks, and clean requests. Labels are binary: `1` for attack, `0` for normal. CVSS scores are included in the dataset but are not used as training features in v2.0.

### Limitations of the ML Component

- Logistic Regression is a linear classifier; complex obfuscated payloads may not be caught
- Dataset size (78 samples) is small; model generalizes better with more diverse training data
- The ML service is called synchronously; network failures fall back gracefully to rule-based scoring only
- No model versioning or drift detection in the current implementation

---

## Quick Start

### Prerequisites

- Java 11 or later
- Maven 3.6 or later
- Spring Boot 2.7 or later
- Python 3.8 or later
- pip 21 or later

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Jaganbhasker1122/RASP-for-Java_Web_Applications.git
cd rasp-engine
```

2. Train the ML model and start the ML service:
```bash
cd ml-service/
pip install -r requirements.txt
python train.py
python app.py &
cd ..
```

3. Build and run the Java application:
```bash
mvn clean package
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
4. Check the server console for detailed detection logs including ML probability

---

## Demo and Testing

### Included Attack Examples

The demo UI provides several predefined attack payloads:

**SQL Injection Example:**
```
/?username=admin' OR '1'='1
```
Pattern detected: SQL boolean operator `OR` with logic manipulation. ML probability: ~0.94

**XSS Example:**
```
/?search=<script>alert('XSS')</script>
```
Pattern detected: Script tag injection attempt. ML probability: ~0.91

**Path Traversal Example:**
```
/?file=../../../../etc/passwd
```
Pattern detected: Directory traversal sequence `../`. ML probability: ~0.87

### Realistic Attack Detection Example

**Attack Scenario:**
A user submits a login form with a crafted payload instead of a username.

**Request:**
```
POST /login?username=admin' OR '1'='1&password=anything
```

**RASP Analysis Process:**

1. Extract payload: `admin' OR '1'='1`
2. Analyze for SQL patterns → 70 points
3. Call ML service → probability: 0.94, prediction: attack → +30 points (ML high)
4. Final score: 100 points
5. Decision: Score >= 60 → BLOCK

**Server Log Output:**
```
[RASP] ============================================
[RASP] SECURITY THREAT DETECTED
[RASP] ============================================
[RASP] Request URI: /login?username=admin' OR '1'='1
[RASP] Detected Attack Types: [SQL_INJECTION]
[RASP] ML Prediction: attack (probability: 0.94)
[RASP] Risk Score: 100
[RASP] Timestamp: 2024-01-15T10:30:45.123Z
[RASP] Status: BLOCKED
[RASP] ============================================
```

**User Experience:**
- User sees "403 Forbidden" error page
- Request never reaches application login controller
- Legitimate request with `username=john` passes through normally (score: 0, ML probability: ~0.02)

### Manual Testing

Start both services and test with curl:

```bash
# Test SQL injection (should be blocked)
curl "http://localhost:8080/?username=admin' OR '1'='1"

# Test XSS (should be blocked)
curl "http://localhost:8080/?search=<script>alert('xss')</script>"

# Test path traversal (should be blocked)
curl "http://localhost:8080/?file=../../../../etc/passwd"

# Test normal request (should succeed)
curl "http://localhost:8080/?username=john&id=123"

# Test ML service directly
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"payload": "admin'\'' OR '\''1'\''='\''1"}'
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
  ml-service-url: http://localhost:5000/predict  # ML microservice endpoint
  ml-enabled: true                # Enable ML scoring signal
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
│   │   │   ├── scoring/          # Risk scoring logic (rule + ML combined)
│   │   │   ├── controller/       # Web controllers (demo UI)
│   │   │   └── utils/            # Utility classes
│   │   └── resources/
│   │       ├── application.yml   # Configuration file
│   │       └── templates/
│   │           ├── index.html    # Demo home page
│   │           └── rasp-blocked.html  # Forbidden page
│   └── test/
│       └── java/                 # Unit tests
├── ml-service/
│   ├── app.py                    # Flask prediction API
│   ├── train.py                  # Model training script
│   ├── dataset.csv               # Labeled payload training data
│   ├── model.pkl                 # Trained Logistic Regression model (generated)
│   └── requirements.txt          # Python dependencies
├── pom.xml                       # Maven dependencies
└── README.md                     # This file
```

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | Java 11+ | Core RASP implementation |
| Framework | Spring Boot 2.7+ | Application framework and filter configuration |
| Security | Servlet Filter API | HTTP request interception and filtering |
| ML Service | Python 3.8+, Flask | Payload classification microservice |
| ML Model | scikit-learn (Logistic Regression) | Probability-based attack detection |
| ML Serving | Waitress | Production-ready WSGI server for Flask |
| Frontend | HTML5, CSS3, JavaScript | Demo interface |
| Build Tool | Maven 3.6+ | Project compilation and dependency management |
| Testing | JUnit 5, Mockito | Unit testing framework |

---

## Limitations

This is an educational project demonstrating RASP concepts with ML integration. The following limitations should be noted:

**Query Parameters Only:**
- Currently analyzes only URL query parameters
- POST body parameters, headers, and cookies are not analyzed (planned for v3.0)
- JSON payload inspection is not included

**Detection Scope:**
- Rule-based matching may not catch deeply obfuscated or novel attacks
- ML model trained on 78 samples; larger datasets would improve generalization
- Logistic Regression is a linear model; non-linear attack patterns may be missed
- False positives possible for legitimate encoded data (e.g., mathematical formulas)

**ML Service:**
- Called synchronously; if the Python service is down, scoring falls back to rules only
- No model versioning, A/B testing, or drift monitoring
- Feature set is intentionally simple for educational clarity

**Performance Considerations:**
- Designed for educational purposes; production deployment requires additional hardening
- No distributed caching or optimization for high-traffic scenarios
- Request filtering overhead approximately 1–3ms per request (including ML call)

**Response Filtering:**
- Only request inspection is implemented
- Response filtering or data exfiltration prevention is not included

---

## Future Enhancements

### Version 3.0 (Planned)
- POST body and JSON payload inspection
- HTTP header analysis and validation
- Cookie-based attack detection
- Enhanced logging with structured formats (JSON/CSV export)
- Larger, more diverse training dataset for improved ML accuracy
- Model retraining pipeline with new attack samples

### Version 4.0 (Planned)
- Advanced anomaly detection using ensemble models or neural networks
- Response filtering and data protection
- Distributed logging integration (ELK stack)
- Online learning: model updates from production traffic (with human review)

### Community Features (Long-term)
- Admin dashboard for rule management and ML model monitoring
- Security analytics and reporting
- Rate limiting and DDoS mitigation
- Webhook-based security event notifications

---

## Learning Outcomes

Working with this project helps you understand:

- **Runtime Security:** How security controls can be enforced at the application layer
- **Request Processing:** Servlet filter architecture and HTTP request lifecycle
- **Threat Detection:** Common web attack patterns and detection techniques
- **ML for Security:** Feature engineering, model training, and integrating ML predictions into a security pipeline
- **Risk Assessment:** Multi-signal scoring combining rules and ML probabilities
- **Microservice Communication:** Java calling a Python REST API for inference
- **Secure Architecture:** Separation of concerns and extensible design
- **OWASP Top 10:** Practical protection against common web vulnerabilities
- **Spring Boot Security:** Security configuration and filter chains
- **Testing Security:** Testing threat detection and edge cases

This project is suitable for:
- Computer science students learning application security and applied ML
- Cybersecurity role interviews (demonstrates practical security + ML knowledge)
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

# Start ML service
cd ml-service && python train.py && python app.py &
cd ..

# Start Java app
mvn clean install
mvn spring-boot:run
```

### Code Guidelines

- Follow Google Java Style Guide
- Write meaningful variable and method names
- Add unit tests for new detection rules
- Document public methods and complex logic
- Keep changes focused and well-scoped
- For ML changes: include updated model accuracy metrics in the PR description

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
- [scikit-learn Logistic Regression](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html)
- [Flask Documentation](https://flask.palletsprojects.com/)

---

**Author:** Gurram Jagan Bhasker

This project is provided for educational purposes to help understand runtime application security concepts, RASP architecture, and ML-assisted threat detection.
