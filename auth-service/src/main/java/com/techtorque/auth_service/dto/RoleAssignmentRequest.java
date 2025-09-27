package com.techtorque.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for role assignment/revocation
 * Used for POST /api/v1/users/{username}/roles endpoint
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleAssignmentRequest {
    
    @NotBlank(message = "Role name is required")
    private String roleName;
    
    @NotNull(message = "Action is required")
    private RoleAction action;
    
    public enum RoleAction {
        ASSIGN, REVOKE
    }
}