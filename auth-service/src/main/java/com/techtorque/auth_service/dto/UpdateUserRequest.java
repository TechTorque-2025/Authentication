package com.techtorque.auth_service.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for updating user details
 * Used for PUT/PATCH /api/v1/users/{username} endpoint
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UpdateUserRequest {
    
    @Email(message = "Please provide a valid email address")
    private String email;
    
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Username can only contain letters, numbers, underscores, and hyphens")
    private String username;
    
    private Boolean enabled;
}