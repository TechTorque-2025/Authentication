package com.techtorque.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for creating admin accounts
 * Only existing admins can use this endpoint
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreateAdminRequest {
    
    private String username;
    private String email;
    private String password;
    
    // Optional: Additional admin-specific fields
    private String firstName;
    private String lastName;
}