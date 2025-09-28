package com.techtorque.auth_service.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI 3.0 configuration for the TechTorque Authentication Service
 * 
 * This configuration:
 * 1. Defines API documentation metadata
 * 2. Sets up JWT Bearer token authentication scheme
 * 3. Configures the authorization button in Swagger UI
 * 4. Defines server information
 */
@Configuration
@OpenAPIDefinition(
    info = @Info(
        title = "TechTorque Auth Service API",
        version = "1.0.0",
        description = """
            Authentication and User Management API for TechTorque Auto Service Platform.
            
            This API provides:
            - User authentication (login/logout)
            - User registration and management
            - Role-based access control (RBAC)
            - JWT token management
            - Account security features (rate limiting, lockout protection)
            
            ## Security
            Most endpoints require JWT authentication. Use the 'Authorize' button above to provide your Bearer token.
            
            ## Rate Limiting
            Login attempts are rate-limited to prevent brute force attacks:
            - Maximum 3 failed attempts per account
            - 15-minute lockout after exceeding limit
            - Automatic reset on successful login
            """,
        contact = @Contact(
            name = "TechTorque Development Team",
            email = "dev@techtorque.com",
            url = "https://github.com/TechTorque-2025"
        ),
        license = @License(
            name = "MIT License",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    servers = {
        @Server(
            url = "http://localhost:8081",
            description = "Development Server"
        ),
        @Server(
            url = "https://api.techtorque.com",
            description = "Production Server"
        )
    },
    security = {
        @SecurityRequirement(name = "bearerAuth")
    }
)
@SecurityScheme(
    name = "bearerAuth",
    description = """
        JWT Bearer Token Authentication
        
        To obtain a token:
        1. Use the /api/v1/auth/login endpoint with valid credentials
        2. Copy the 'token' value from the response
        3. Click the 'Authorize' button above
        4. Enter: <your-token-here>
        5. Click 'Authorize' to apply the token to all requests

        Example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        """,
    type = SecuritySchemeType.HTTP,
    scheme = "bearer",
    bearerFormat = "JWT",
    in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {
    // This configuration class uses annotations only
    // Spring Boot will automatically pick up the @OpenAPIDefinition and @SecurityScheme annotations
}