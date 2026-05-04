package com.rasplab.rasplab.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.rasplab.rasplab.context.HttpRequestContext;
import com.rasplab.rasplab.detection.DetectionResult;
import com.rasplab.rasplab.detection.RaspDetector;
import com.rasplab.rasplab.ml.MlService;

import java.io.IOException;
import java.util.Collections;
import java.util.stream.Collectors;

@Component
public class RaspFilter implements Filter {

    private final RaspDetector detector;
    private final MlService mlService;

    @Autowired
    public RaspFilter(RaspDetector detector, MlService mlService) {
        this.detector = detector;
        this.mlService = mlService;
    }

    @Override
    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if (req.getRequestURI().startsWith("/css") || req.getRequestURI().startsWith("/js") || req.getRequestURI().endsWith(".html")) {
            chain.doFilter(request, response);
            return;
        }

        // Build request context
        HttpRequestContext ctx = new HttpRequestContext();
        ctx.setUri(req.getRequestURI());
        ctx.setMethod(req.getMethod());
        ctx.setQuery(req.getQueryString());
        ctx.setHeaders(
                Collections.list(req.getHeaderNames())
                        .stream()
                        .collect(Collectors.toMap(
                                h -> h.toLowerCase(),
                                req::getHeader)));

        // Log request
        System.out.println(
                "[RASP] " + ctx.getMethod() +
                        " " + ctx.getUri() +
                        " | Query=" + ctx.getQuery());

        // Run detection
        DetectionResult result = detector.analyze(ctx);
        int ruleScore = result.getRiskScore();

        // Get payload for ML
        String payloadForMl = req.getQueryString() != null ? req.getQueryString() : "";
        if (payloadForMl.isEmpty() && ctx.getHeaders().containsKey("user-agent")) {
             payloadForMl += ctx.getHeaders().get("user-agent"); // basic fallback
        }

        // Ask Python ML Service
        double mlProbability = mlService.getProbability(payloadForMl);
        
        // Final ensemble score
        double finalScore = ruleScore + (mlProbability * 100);

        // -------- RISK-BASED DECISION --------
        if (finalScore >= 100) {

            System.out.println(
                    "[RASP-BLOCKED] " +
                            result.getAttackType() +
                            " | FinalScore=" + finalScore + " (Rule=" + ruleScore + ", ML=" + mlProbability + ")" +
                            " | Reason: " + result.getReason());

            String accept = req.getHeader("Accept");

            res.setStatus(HttpServletResponse.SC_FORBIDDEN);

            // 🧠 Browser request → show HTML page
            if (accept != null && accept.contains("text/html")) {
                res.sendRedirect("/rasp-blocked.html");
                return;
            }

            // 🧠 API / AJAX request → return JSON
            res.setContentType("application/json");
            res.getWriter().write(String.format("""
                            {
                              "blocked": true,
                              "message": "Request blocked due to security policy",
                              "ruleScore": %d,
                              "mlProbability": %.2f,
                              "finalScore": %.2f,
                              "attackType": "%s"
                            }
                            """,
                    ruleScore, mlProbability, finalScore, result.getAttackType()));

            return;
        }

        res.setHeader("X-RASP-Final-Score", String.valueOf(finalScore));

        // Allow request
        chain.doFilter(request, response);
    }
}
