package com.techtorque.auth_service.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Custom CORS filter that ensures CORS headers are added to ALL responses,
 * including redirects and error responses.
 *
 * This filter runs at the servlet level (before Spring Security) with high priority
 * to ensure CORS headers are included on every response regardless of what happens downstream.
 *
 * NOTE: This filter is DISABLED because CORS is handled centrally by the API Gateway.
 * The API Gateway applies CORS headers to all responses, so backend services should not
 * add CORS headers to avoid duplication.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorsFilter implements Filter {

    @Value("${app.cors.allowed-origins:http://localhost:3000,http://127.0.0.1:3000}")
    private String allowedOrigins;

    @Override
    public void init(FilterConfig filterConfig) {
        // Initialize filter
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        // CORS is handled by the API Gateway, so we skip CORS header injection here
        // Just pass the request through without adding CORS headers
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Cleanup
    }

    /**
     * Check if the given origin is in the allowed list
     */
    private boolean isOriginAllowed(String origin) {
        String[] origins = allowedOrigins.split(",");
        for (String allowed : origins) {
            if (allowed.trim().equals(origin)) {
                return true;
            }
        }
        return false;
    }
}
