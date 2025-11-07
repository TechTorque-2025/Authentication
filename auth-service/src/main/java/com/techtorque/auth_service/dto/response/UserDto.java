package com.techtorque.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Data Transfer Object for User information
 * Used to transfer user data without exposing sensitive information
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDto {
    
    private Long id;
    private String username;
    private String email;
    private String fullName;
    private String phone;
    private String address;
    private String profilePhoto;
    private Boolean enabled;
    private Boolean emailVerified;
    private LocalDateTime createdAt;
    private Set<String> roles; // Role names as strings
    private Set<String> permissions; // Permission names as strings
}