package com.techtorque.auth_service.service;

import com.techtorque.notification.grpc.DeliveryStatus;
import com.techtorque.notification.grpc.EmailType;
import com.techtorque.notification.grpc.NotificationEmailServiceGrpc;
import com.techtorque.notification.grpc.SendEmailRequest;
import com.techtorque.notification.grpc.SendEmailResponse;
import io.grpc.StatusRuntimeException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.client.inject.GrpcClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

/**
 * Bridges auth-service events to the notification-service via gRPC.
 */
@Service
@Slf4j
public class EmailService {

    @GrpcClient("notification-email")
    private NotificationEmailServiceGrpc.NotificationEmailServiceBlockingStub emailStub;

    @Value("${app.email.enabled:true}")
    private boolean emailEnabled;

    @Value("${app.frontend.url:http://localhost:3000}")
    private String frontendUrl;

    @Value("${notification.grpc.deadline-ms:5000}")
    private long deadlineMs;

    @Value("${notification.grpc.enabled:true}")
    private boolean grpcEnabled;

    /**
     * Initiates email verification workflow through notification-service.
     */
    public void sendVerificationEmail(String toEmail, String username, String token) {
        Map<String, String> variables = new HashMap<>();
        variables.put("token", token);
        variables.put("verificationUrl", frontendUrl + "/auth/verify-email?token=" + token);
        sendEmail(toEmail, username, EmailType.EMAIL_TYPE_VERIFICATION, variables);
    }

    /**
     * Requests a password reset email from notification-service.
     */
    public void sendPasswordResetEmail(String toEmail, String username, String token) {
        Map<String, String> variables = new HashMap<>();
        variables.put("token", token);
        variables.put("resetUrl", frontendUrl + "/auth/reset-password?token=" + token);
        sendEmail(toEmail, username, EmailType.EMAIL_TYPE_PASSWORD_RESET, variables);
    }

    /**
     * Dispatches welcome email once the account is verified.
     */
    public void sendWelcomeEmail(String toEmail, String username) {
        Map<String, String> variables = new HashMap<>();
        variables.put("dashboardUrl", frontendUrl + "/dashboard");
        sendEmail(toEmail, username, EmailType.EMAIL_TYPE_WELCOME, variables);
    }

    private void sendEmail(String toEmail, String username, EmailType type, Map<String, String> variables) {
        if (!emailEnabled || !grpcEnabled) {
            log.info("Notification email dispatch disabled. Skipping {} email for {}", type, username);
            return;
        }

        NotificationEmailServiceGrpc.NotificationEmailServiceBlockingStub stubToUse = emailStub;
        if (deadlineMs > 0) {
            stubToUse = stubToUse.withDeadlineAfter(deadlineMs, TimeUnit.MILLISECONDS);
        }

        SendEmailRequest.Builder builder = SendEmailRequest.newBuilder()
                .setTo(toEmail)
                .setUsername(username == null ? "" : username)
                .setType(type)
                .setCorrelationId(UUID.randomUUID().toString());

        if (!CollectionUtils.isEmpty(variables)) {
            builder.putAllVariables(variables);
        }

        try {
            SendEmailResponse response = stubToUse.sendTransactionalEmail(builder.build());
            if (response.getStatus() == DeliveryStatus.DELIVERY_STATUS_ACCEPTED) {
                log.info("Notification-service accepted {} email for {} (id={})", type, toEmail, response.getMessageId());
            } else {
                log.warn("Notification-service rejected {} email for {}: {}", type, toEmail, response.getDetail());
            }
        } catch (StatusRuntimeException ex) {
            log.error("gRPC call failed while sending {} email to {}: {}", type, toEmail, ex.getStatus(), ex);
        } catch (Exception ex) {
            log.error("Unexpected error while sending {} email to {}: {}", type, toEmail, ex.getMessage(), ex);
        }
    }
}
