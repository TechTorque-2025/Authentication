package com.techtorque.auth_service.config;

import jakarta.servlet.*;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

import java.io.IOException;

/**
 * ⚠️ DO NOT ENABLE THIS FILTER ⚠️
 * 
 * CORS is handled centrally by the API Gateway (API_Gateway/cmd/gateway/main.go).
 * All client requests go through the API Gateway, which applies CORS headers.
 * 
 * Enabling CORS at the microservice level will:
 * - Create duplicate CORS headers
 * - Cause CORS preflight issues
 * - Break browser security
 * 
 * This class is kept for reference only and should remain DISABLED.
 * 
 * @deprecated CORS must be handled by API Gateway only
 */
// @Component - DO NOT ENABLE: CORS is handled by API Gateway
@Deprecated
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorsFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) {
        // Initialize filter
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // This filter is DISABLED and should never be called
        // CORS is handled by the API Gateway
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Cleanup
    }
}
