package com.techtorque.auth_service.config;

import com.techtorque.auth_service.service.EmailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration for Email Service
 * Ensures EmailService bean is properly registered
 */
@Configuration
public class EmailConfig {

    @Bean
    public EmailService emailService() {
        return new EmailService();
    }
}

