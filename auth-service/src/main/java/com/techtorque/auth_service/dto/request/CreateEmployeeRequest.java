package com.techtorque.auth_service.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for creating employee accounts
 * Only admins can use this endpoint
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreateEmployeeRequest {
    
    private String username;
    private String email;
    private String password;
    
    // Optional: Additional employee-specific fields
    private String firstName;
    private String lastName;
    private String department;
}