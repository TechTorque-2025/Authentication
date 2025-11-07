package com.techtorque.auth_service.dto.response;

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
    private String refreshToken;
    private String type = "Bearer";
    private String username;
    private String email;
    private Set<String> roles;

}