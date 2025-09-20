package com.techtorque.auth_service.controller;

import com.techtorque.auth_service.dto.LoginRequest;
import com.techtorque.auth_service.dto.LoginResponse;
import com.techtorque.auth_service.service.UserService;
import com.techtorque.auth_service.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/")
public class AuthController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private JwtUtil jwtUtil;
    
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            if (userService.authenticate(loginRequest.getUsername(), loginRequest.getPassword())) {
                String token = jwtUtil.generateToken(loginRequest.getUsername());
                LoginResponse response = new LoginResponse(token, loginRequest.getUsername());
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("{\"error\":\"Invalid credentials\"}");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("{\"error\":\"Internal server error\"}");
        }
    }
    
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("{\"status\":\"UP\"}");
    }
}