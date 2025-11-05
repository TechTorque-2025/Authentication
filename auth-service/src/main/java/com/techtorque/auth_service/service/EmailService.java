package com.techtorque.auth_service.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

/**
 * Service for sending emails
 */
@Service
@Slf4j
public class EmailService {
    
    @Autowired(required = false)
    private JavaMailSender mailSender;
    
    @Value("${spring.mail.username:noreply@techtorque.com}")
    private String fromEmail;
    
    @Value("${app.frontend.url:http://localhost:3000}")
    private String frontendUrl;
    
    @Value("${app.email.enabled:false}")
    private boolean emailEnabled;
    
    /**
     * Send email verification link
     */
    public void sendVerificationEmail(String toEmail, String username, String token) {
        if (!emailEnabled) {
            log.info("Email disabled. Verification token for {}: {}", username, token);
            return;
        }
        
        try {
            String verificationUrl = frontendUrl + "/verify-email?token=" + token;
            
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("TechTorque - Verify Your Email Address");
            message.setText(String.format(
                "Hello %s,\n\n" +
                "Thank you for registering with TechTorque!\n\n" +
                "Please click the link below to verify your email address:\n" +
                "%s\n\n" +
                "This link will expire in 24 hours.\n\n" +
                "If you did not create an account, please ignore this email.\n\n" +
                "Best regards,\n" +
                "TechTorque Team",
                username, verificationUrl
            ));
            
            if (mailSender != null) {
                mailSender.send(message);
                log.info("Verification email sent to: {}", toEmail);
            } else {
                log.warn("Mail sender not configured. Email not sent to: {}", toEmail);
            }
        } catch (Exception e) {
            log.error("Failed to send verification email to {}: {}", toEmail, e.getMessage());
        }
    }
    
    /**
     * Send password reset email
     */
    public void sendPasswordResetEmail(String toEmail, String username, String token) {
        if (!emailEnabled) {
            log.info("Email disabled. Password reset token for {}: {}", username, token);
            return;
        }
        
        try {
            String resetUrl = frontendUrl + "/reset-password?token=" + token;
            
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("TechTorque - Password Reset Request");
            message.setText(String.format(
                "Hello %s,\n\n" +
                "We received a request to reset your password.\n\n" +
                "Please click the link below to reset your password:\n" +
                "%s\n\n" +
                "This link will expire in 1 hour.\n\n" +
                "If you did not request a password reset, please ignore this email " +
                "and your password will remain unchanged.\n\n" +
                "Best regards,\n" +
                "TechTorque Team",
                username, resetUrl
            ));
            
            if (mailSender != null) {
                mailSender.send(message);
                log.info("Password reset email sent to: {}", toEmail);
            } else {
                log.warn("Mail sender not configured. Email not sent to: {}", toEmail);
            }
        } catch (Exception e) {
            log.error("Failed to send password reset email to {}: {}", toEmail, e.getMessage());
        }
    }
    
    /**
     * Send welcome email after verification
     */
    public void sendWelcomeEmail(String toEmail, String username) {
        if (!emailEnabled) {
            log.info("Email disabled. Welcome email skipped for: {}", username);
            return;
        }
        
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("Welcome to TechTorque!");
            message.setText(String.format(
                "Hello %s,\n\n" +
                "Welcome to TechTorque! Your email has been successfully verified.\n\n" +
                "You can now:\n" +
                "- Register your vehicles\n" +
                "- Book service appointments\n" +
                "- Track service progress\n" +
                "- Request custom modifications\n\n" +
                "Visit %s to get started.\n\n" +
                "Best regards,\n" +
                "TechTorque Team",
                username, frontendUrl
            ));
            
            if (mailSender != null) {
                mailSender.send(message);
                log.info("Welcome email sent to: {}", toEmail);
            } else {
                log.warn("Mail sender not configured. Email not sent to: {}", toEmail);
            }
        } catch (Exception e) {
            log.error("Failed to send welcome email to {}: {}", toEmail, e.getMessage());
        }
    }
}
