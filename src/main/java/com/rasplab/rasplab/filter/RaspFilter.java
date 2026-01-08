package com.rasplab.rasplab.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;

import com.rasplab.rasplab.context.HttpRequestContext;
import com.rasplab.rasplab.detection.DetectionResult;
import com.rasplab.rasplab.detection.RaspDetector;

import java.io.IOException;
import java.util.Collections;
import java.util.stream.Collectors;

@Component
public class RaspFilter implements Filter {

        private final RaspDetector detector;

        public RaspFilter(RaspDetector detector) {
                this.detector = detector;
        }

        @Override
        public void doFilter(
                        ServletRequest request,
                        ServletResponse response,
                        FilterChain chain) throws IOException, ServletException {

                HttpServletRequest req = (HttpServletRequest) request;
                HttpServletResponse res = (HttpServletResponse) response;

                // Build request context
                HttpRequestContext ctx = new HttpRequestContext();
                ctx.setUri(req.getRequestURI());
                ctx.setMethod(req.getMethod());
                ctx.setQuery(req.getQueryString());
                ctx.setHeaders(
                                Collections.list(req.getHeaderNames())
                                                .stream()
                                                .collect(Collectors.toMap(
                                                                h -> h,
                                                                req::getHeader)));

                // Log request
                System.out.println(
                                "[RASP] " + ctx.getMethod() +
                                                " " + ctx.getUri() +
                                                " | Query=" + ctx.getQuery());

                // Run detection
                DetectionResult result = detector.analyze(ctx);

                // -------- RISK-BASED DECISION --------
                if (result.getRiskScore() >= 60) {

                        System.out.println(
                                        "[RASP-BLOCKED] " +
                                                        result.getAttackType() +
                                                        " | Risk=" + result.getRiskScore() +
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
                        res.getWriter().write("""
                                        {
                                          "blocked": true,
                                          "message": "Request blocked due to security policy",
                                          "riskScore": %d,
                                          "attackType": "%s"
                                        }
                                        """.formatted(
                                        result.getRiskScore(),
                                        result.getAttackType()));

                        return;
                }

                // Allow request
                chain.doFilter(request, response);
        }
}
