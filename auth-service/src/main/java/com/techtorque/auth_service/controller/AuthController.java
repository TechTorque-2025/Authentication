package com.techtorque.auth_service.controller;

import com.techtorque.auth_service.dto.request.*;
import com.techtorque.auth_service.dto.response.*;
import com.techtorque.auth_service.service.AuthService;
import com.techtorque.auth_service.service.UserService;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * REST Controller for authentication endpoints
 * Handles login, registration, and health check requests
 */
@RestController
// Class-level request mapping removed — gateway strips prefixes before forwarding
// @RequestMapping("/api/v1/auth")
// CORS handled at the API Gateway; remove @CrossOrigin to avoid conflicts
// @CrossOrigin(origins = "*", maxAge = 3600)
@Tag(name = "Authentication", description = "Authentication and user management endpoints")
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
    @Operation(
        summary = "User Login",
        description = "Authenticate user with username/email and password. Returns JWT token on success. Rate limited to prevent brute force attacks."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Login successful, JWT token returned"),
        @ApiResponse(responseCode = "401", description = "Invalid credentials or account locked"),
        @ApiResponse(responseCode = "400", description = "Invalid request format")
    })
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
    @Operation(
        summary = "Register New User",
        description = "Register a new customer account. Email verification is required before login."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Registration successful, verification email sent"),
        @ApiResponse(responseCode = "400", description = "Invalid request or username/email already exists")
    })
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        String message = authService.registerUser(registerRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiSuccess.of(message));
    }
    
    /**
     * Verify email with token
     */
    @Operation(
        summary = "Verify Email",
        description = "Verify user email address with token sent via email. Returns JWT tokens on success."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Email verified successfully, user logged in"),
        @ApiResponse(responseCode = "400", description = "Invalid, expired, or already used token")
    })
    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@Valid @RequestBody VerifyEmailRequest request, HttpServletRequest httpRequest) {
        LoginResponse response = authService.verifyEmail(request.getToken(), httpRequest);
        return ResponseEntity.ok(response);
    }
    
    /**
     * Resend verification email
     */
    @Operation(
        summary = "Resend Verification Email",
        description = "Resend verification email to the specified address"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Verification email sent successfully"),
        @ApiResponse(responseCode = "400", description = "Email not found or already verified")
    })
    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        String message = authService.resendVerificationEmail(request.getEmail());
        return ResponseEntity.ok(ApiSuccess.of(message));
    }
    
    /**
     * Refresh JWT token
     */
    @Operation(
        summary = "Refresh Access Token",
        description = "Get a new access token using a valid refresh token"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "New access token generated"),
        @ApiResponse(responseCode = "401", description = "Invalid, expired, or revoked refresh token")
    })
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        LoginResponse response = authService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }
    
    /**
     * Logout endpoint
     */
    @Operation(
        summary = "Logout User",
        description = "Logout user and revoke refresh token",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Logged out successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid refresh token")
    })
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Valid @RequestBody LogoutRequest request) {
        authService.logout(request.getRefreshToken());
        return ResponseEntity.ok(ApiSuccess.of("Logged out successfully"));
    }
    
    /**
     * Forgot password - request reset
     */
    @Operation(
        summary = "Forgot Password",
        description = "Request password reset email"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password reset email sent"),
        @ApiResponse(responseCode = "404", description = "Email not found")
    })
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        String message = authService.forgotPassword(request.getEmail());
        return ResponseEntity.ok(ApiSuccess.of(message));
    }
    
    /**
     * Reset password with token
     */
    @Operation(
        summary = "Reset Password",
        description = "Reset password using token from email"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password reset successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid, expired, or already used token")
    })
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordWithTokenRequest request) {
        String message = authService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok(ApiSuccess.of(message));
    }
    
    /**
     * Change password (authenticated users)
     * Note: This endpoint moved to UserController as /users/me/change-password
     * Keeping for backwards compatibility
     */
    @Operation(
        summary = "Change Password",
        description = "Change password for authenticated user. Use current password for verification.",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password changed successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid current password"),
        @ApiResponse(responseCode = "401", description = "Authentication required")
    })
    @PutMapping("/change-password")
    @PreAuthorize("hasRole('CUSTOMER') or hasRole('EMPLOYEE') or hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
    public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordRequest changeRequest) {
        try {
            Authentication authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            
            userService.changeUserPassword(username, changeRequest.getCurrentPassword(), changeRequest.getNewPassword());
            return ResponseEntity.ok(ApiSuccess.of("Password changed successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(ApiSuccess.of("Error: " + e.getMessage()));
        }
    }

    
    // --- NEW ENDPOINT FOR CREATING EMPLOYEES ---
    /**
     * ADMIN-ONLY endpoint for creating a new employee account.
     * @param createEmployeeRequest DTO with username, email, and password.
     * @return A success or error message.
     */
    @Operation(
        summary = "Create Employee Account",
        description = "Create a new employee account. Requires ADMIN role.",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Employee account created successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid request or username already exists"),
        @ApiResponse(responseCode = "401", description = "Authentication required"),
        @ApiResponse(responseCode = "403", description = "Admin role required")
    })
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