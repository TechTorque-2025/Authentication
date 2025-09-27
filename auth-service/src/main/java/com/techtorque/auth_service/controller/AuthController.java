package com.techtorque.auth_service.controller;

import com.techtorque.auth_service.dto.CreateEmployeeRequest;
import com.techtorque.auth_service.dto.CreateAdminRequest;
import com.techtorque.auth_service.dto.LoginRequest;
import com.techtorque.auth_service.dto.LoginResponse;
import com.techtorque.auth_service.dto.RegisterRequest;
import com.techtorque.auth_service.service.AuthService;
import com.techtorque.auth_service.service.UserService;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import com.techtorque.auth_service.dto.ApiSuccess;

/**
 * REST Controller for authentication endpoints
 * Handles login, registration, and health check requests
 */
@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {
    
    @Autowired
    private AuthService authService;
    
    // --- NEW DEPENDENCY ---
    // We need UserService to call the createEmployee method
    @Autowired
    private UserService userService;
    
    /**
     * User login endpoint
     * @param loginRequest Login credentials
     * @return JWT token and user details
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        LoginResponse loginResponse = authService.authenticateUser(loginRequest, request);
        return ResponseEntity.ok(loginResponse);
    }
    
    /**
     * User registration endpoint
     * @param registerRequest Registration details
     * @return Success message
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        String message = authService.registerUser(registerRequest);
        return ResponseEntity.ok(ApiSuccess.of(message));
    }
    
    // --- NEW ENDPOINT FOR CREATING EMPLOYEES ---
    /**
     * ADMIN-ONLY endpoint for creating a new employee account.
     * @param createEmployeeRequest DTO with username, email, and password.
     * @return A success or error message.
     */
    @PostMapping("/users/employee")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createEmployee(@Valid @RequestBody CreateEmployeeRequest createEmployeeRequest) {
        try {
            // Now we are calling the method that was previously unused
            userService.createEmployee(
                createEmployeeRequest.getUsername(),
                createEmployeeRequest.getEmail(),
                createEmployeeRequest.getPassword()
            );
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiSuccess.of("Employee account created successfully!"));
        } catch (RuntimeException e) {
            // Catches errors like "Username already exists"
            return ResponseEntity.badRequest().body(ApiSuccess.of("Error: " + e.getMessage()));
        }
    }

    // --- NEW ENDPOINT FOR CREATING ADMINS (SUPER_ADMIN ONLY) ---
    /**
     * SUPER_ADMIN-ONLY endpoint for creating a new admin account.
     * @param createAdminRequest DTO with username, email, and password.
     * @return A success or error message.
     */
    @PostMapping("/users/admin")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<?> createAdmin(@Valid @RequestBody CreateAdminRequest createAdminRequest) {
        try {
            userService.createAdmin(
                createAdminRequest.getUsername(),
                createAdminRequest.getEmail(),
                createAdminRequest.getPassword()
            );
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiSuccess.of("Admin account created successfully!"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(ApiSuccess.of("Error: " + e.getMessage()));
        }
    }
    
    /**
     * Health check endpoint
     * @return Service status
     */
    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(ApiSuccess.of("Authentication Service is running!"));
    }
    
    /**
     * Test endpoint for authenticated users
     * @return Test message
     */
    @GetMapping("/test")
    public ResponseEntity<?> test() {
        return ResponseEntity.ok(ApiSuccess.of("Test endpoint accessible!"));
    }

}