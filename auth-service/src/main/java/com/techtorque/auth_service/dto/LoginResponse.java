package com.techtorque.auth_service.dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginResponse {
    
    private String token;
    private String type = "Bearer";
    private String username;
    private String email;
    private Set<String> roles;
    
    public LoginResponse(String token, String username, String email, Set<String> roles) {
        this.token = token;
        this.type = "Bearer";
        this.username = username;
        this.email = email;
        this.roles = roles;
    }
}