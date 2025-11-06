package com.techtorque.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for admin password reset
 * Used for POST /api/v1/users/{username}/reset-password endpoint
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ResetPasswordRequest {
    
    @NotBlank(message = "New password is required")
    @Size(min = 8, max = 100, message = "New password must be between 8 and 100 characters")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]+$",
             message = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&#)")
    private String newPassword;
}