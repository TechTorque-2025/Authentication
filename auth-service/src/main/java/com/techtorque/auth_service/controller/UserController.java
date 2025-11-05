package com.techtorque.auth_service.controller;

import com.techtorque.auth_service.dto.request.*;
import com.techtorque.auth_service.dto.response.*;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.List;
import java.util.stream.Collectors;

/**
 * REST Controller for user management endpoints.
 * Endpoints in this controller are accessible to users with ADMIN or SUPER_ADMIN roles.
 */
@RestController
@RequestMapping("/users")
// CORS handled by API Gateway; remove @CrossOrigin to avoid conflicts
// @CrossOrigin(origins = "*", maxAge = 3600)
@PreAuthorize("hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
@Tag(name = "User Management", description = "User management endpoints (Admin/Super Admin only)")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

  @Autowired
  private UserService userService;

  @Autowired
  private com.techtorque.auth_service.service.PreferencesService preferencesService;

  /**
   * Get a list of all users in the system.
   */
  @GetMapping
  public ResponseEntity<List<UserDto>> getAllUsers() {
    List<UserDto> users = userService.findAllUsers().stream()
            .map(this::convertToDto)
            .collect(Collectors.toList());
    return ResponseEntity.ok(users);
  }

  /**
   * Get detailed information for a single user by their username.
   */
  @GetMapping("/{username}")
  public ResponseEntity<UserDto> getUserByUsername(@PathVariable String username) {
    return userService.findByUsername(username)
            .map(user -> ResponseEntity.ok(convertToDto(user)))
            .orElse(ResponseEntity.notFound().build());
  }

  /**
   * Disable a user's account.
   */
  @PostMapping("/{username}/disable")
  public ResponseEntity<?> disableUser(@PathVariable String username) {
    try {
      userService.disableUser(username);
      return ResponseEntity.ok(ApiSuccess.of("User '" + username + "' has been disabled."));
    } catch (RuntimeException e) {
      throw new RuntimeException(e.getMessage());
    }
  }

  /**
   * Enable a user's account.
   */
  @PostMapping("/{username}/enable")
  public ResponseEntity<?> enableUser(@PathVariable String username) {
    try {
      userService.enableUser(username);
      return ResponseEntity.ok(ApiSuccess.of("User '" + username + "' has been enabled."));
    } catch (RuntimeException e) {
      throw new RuntimeException(e.getMessage());
    }
  }
  
  /**
   * Unlock a user's login lock (admin only)
   */
  @PostMapping("/{username}/unlock")
  @PreAuthorize("hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
  public ResponseEntity<?> unlockUser(@PathVariable String username) {
    userService.clearLoginLock(username);
    return ResponseEntity.ok(ApiSuccess.of("Login lock cleared for user: " + username));
  }

  /**
   * Delete a user from the system permanently.
   */
  @DeleteMapping("/{username}")
  public ResponseEntity<?> deleteUser(@PathVariable String username) {
    try {
      userService.deleteUser(username);
      return ResponseEntity.ok(ApiSuccess.of("User '" + username + "' has been deleted."));
    } catch (RuntimeException e) {
      throw new RuntimeException(e.getMessage());
    }
  }

  /**
   * Update a user's details (admin only)
   * PUT /api/v1/users/{username}
   */
  @PutMapping("/{username}")
  public ResponseEntity<?> updateUser(@PathVariable String username, 
                                     @Valid @RequestBody UpdateUserRequest updateRequest) {
    try {
      User updatedUser = userService.updateUserDetails(
          username,
          updateRequest.getUsername(),
          updateRequest.getEmail(),
          updateRequest.getEnabled()
      );
      return ResponseEntity.ok(convertToDto(updatedUser));
    } catch (RuntimeException e) {
      throw new RuntimeException(e.getMessage());
    }
  }

  /**
   * Reset a user's password (admin only)
   * POST /api/v1/users/{username}/reset-password
   */
  @PostMapping("/{username}/reset-password")
  public ResponseEntity<?> resetUserPassword(@PathVariable String username,
                                           @Valid @RequestBody ResetPasswordRequest resetRequest) {
    try {
      userService.resetUserPassword(username, resetRequest.getNewPassword());
      return ResponseEntity.ok(ApiSuccess.of("Password reset successfully for user: " + username));
    } catch (RuntimeException e) {
      throw new RuntimeException(e.getMessage());
    }
  }

  /**
   * Assign or revoke a role to/from a user (admin only)
   * POST /api/v1/users/{username}/roles
   */
  @PostMapping("/{username}/roles")
  public ResponseEntity<?> manageUserRole(@PathVariable String username,
                                         @Valid @RequestBody RoleAssignmentRequest roleRequest) {
    try {
      if (roleRequest.getAction() == RoleAssignmentRequest.RoleAction.ASSIGN) {
        userService.assignRoleToUser(username, roleRequest.getRoleName());
        return ResponseEntity.ok(ApiSuccess.of(
            "Role '" + roleRequest.getRoleName() + "' assigned to user: " + username));
      } else {
        userService.revokeRoleFromUser(username, roleRequest.getRoleName());
        return ResponseEntity.ok(ApiSuccess.of(
            "Role '" + roleRequest.getRoleName() + "' revoked from user: " + username));
      }
    } catch (AccessDeniedException ade) {
      // Specific handling for access denied so clients/tests receive 403 Forbidden
      return ResponseEntity.status(403)
              .body(ApiError.builder()
                      .status(403)
                      .message("Error: " + ade.getMessage())
                      .timestamp(java.time.LocalDateTime.now())
                      .build());
    } catch (RuntimeException e) {
      throw new RuntimeException(e.getMessage());
    }
  }

  /**
   * Get current user's profile (user endpoint)
   * GET /api/v1/users/me
   */
  @Operation(
      summary = "Get Current User Profile",
      description = "Get the profile information of the currently authenticated user. Available to all authenticated users.",
      security = @SecurityRequirement(name = "bearerAuth")
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User profile retrieved successfully"),
      @ApiResponse(responseCode = "401", description = "Authentication required"),
      @ApiResponse(responseCode = "404", description = "User not found")
  })
  @GetMapping("/me")
  @PreAuthorize("hasRole('CUSTOMER') or hasRole('EMPLOYEE') or hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
  public ResponseEntity<?> getCurrentUserProfile() {
    try {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      String username = authentication.getName();
      
      return userService.findByUsername(username)
              .map(user -> ResponseEntity.ok(convertToDto(user)))
              .orElse(ResponseEntity.notFound().build());
    } catch (Exception e) {
      return ResponseEntity.badRequest()
              .body(ApiError.builder()
                      .status(400)
                      .message("Error: " + e.getMessage())
                      .timestamp(java.time.LocalDateTime.now())
                      .build());
    }
  }

  /**
   * Change current user's password (user endpoint)
   * POST /api/v1/users/me/change-password
   */
  @PostMapping("/me/change-password")
  @PreAuthorize("hasRole('CUSTOMER') or hasRole('EMPLOYEE') or hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
  public ResponseEntity<?> changeCurrentUserPassword(@Valid @RequestBody ChangePasswordRequest changeRequest) {
    try {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      String username = authentication.getName();
      
      userService.changeUserPassword(username, changeRequest.getCurrentPassword(), changeRequest.getNewPassword());
      return ResponseEntity.ok(ApiSuccess.of("Password changed successfully"));
    } catch (RuntimeException e) {
      return ResponseEntity.badRequest()
              .body(ApiError.builder()
                      .status(400)
                      .message("Error: " + e.getMessage())
                      .timestamp(java.time.LocalDateTime.now())
                      .build());
    }
  }

  /**
   * Update current user's profile
   * PUT /users/profile
   */
  @Operation(
      summary = "Update User Profile",
      description = "Update profile information for the currently authenticated user",
      security = @SecurityRequirement(name = "bearerAuth")
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Profile updated successfully"),
      @ApiResponse(responseCode = "401", description = "Authentication required"),
      @ApiResponse(responseCode = "400", description = "Invalid request data")
  })
  @PutMapping("/profile")
  @PreAuthorize("hasRole('CUSTOMER') or hasRole('EMPLOYEE') or hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
  public ResponseEntity<?> updateProfile(@Valid @RequestBody UpdateProfileRequest updateRequest) {
    try {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      String username = authentication.getName();
      
      com.techtorque.auth_service.entity.User updatedUser = userService.updateProfile(
          username,
          updateRequest.getFullName(),
          updateRequest.getPhone(),
          updateRequest.getAddress()
      );
      
      return ResponseEntity.ok(convertToDto(updatedUser));
    } catch (Exception e) {
      return ResponseEntity.badRequest()
              .body(ApiError.builder()
                      .status(400)
                      .message("Error: " + e.getMessage())
                      .timestamp(java.time.LocalDateTime.now())
                      .build());
    }
  }

  /**
   * Upload profile photo
   * POST /users/profile/photo
   */
  @Operation(
      summary = "Upload Profile Photo",
      description = "Upload or update profile photo. For now, accepts a URL. In production, this would handle file uploads.",
      security = @SecurityRequirement(name = "bearerAuth")
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Photo uploaded successfully"),
      @ApiResponse(responseCode = "401", description = "Authentication required")
  })
  @PostMapping("/profile/photo")
  @PreAuthorize("hasRole('CUSTOMER') or hasRole('EMPLOYEE') or hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
  public ResponseEntity<?> uploadProfilePhoto(@RequestBody java.util.Map<String, String> request) {
    try {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      String username = authentication.getName();
      
      String photoUrl = request.get("photoUrl");
      if (photoUrl == null || photoUrl.isEmpty()) {
        return ResponseEntity.badRequest()
                .body(ApiError.builder()
                        .status(400)
                        .message("Error: photoUrl is required")
                        .timestamp(java.time.LocalDateTime.now())
                        .build());
      }
      
      userService.updateProfilePhoto(username, photoUrl);
      return ResponseEntity.ok(ApiSuccess.of("Profile photo updated successfully"));
    } catch (Exception e) {
      return ResponseEntity.badRequest()
              .body(ApiError.builder()
                      .status(400)
                      .message("Error: " + e.getMessage())
                      .timestamp(java.time.LocalDateTime.now())
                      .build());
    }
  }

  /**
   * Get user preferences
   * GET /users/preferences
   */
  @Operation(
      summary = "Get User Preferences",
      description = "Get preferences for the currently authenticated user",
      security = @SecurityRequirement(name = "bearerAuth")
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Preferences retrieved successfully"),
      @ApiResponse(responseCode = "401", description = "Authentication required")
  })
  @GetMapping("/preferences")
  @PreAuthorize("hasRole('CUSTOMER') or hasRole('EMPLOYEE') or hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
  public ResponseEntity<?> getUserPreferences() {
    try {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      String username = authentication.getName();
      
      UserPreferencesDto preferences = preferencesService.getUserPreferences(username);
      return ResponseEntity.ok(preferences);
    } catch (Exception e) {
      return ResponseEntity.badRequest()
              .body(ApiError.builder()
                      .status(400)
                      .message("Error: " + e.getMessage())
                      .timestamp(java.time.LocalDateTime.now())
                      .build());
    }
  }

  /**
   * Update user preferences
   * PUT /users/preferences
   */
  @Operation(
      summary = "Update User Preferences",
      description = "Update preferences for the currently authenticated user",
      security = @SecurityRequirement(name = "bearerAuth")
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Preferences updated successfully"),
      @ApiResponse(responseCode = "401", description = "Authentication required")
  })
  @PutMapping("/preferences")
  @PreAuthorize("hasRole('CUSTOMER') or hasRole('EMPLOYEE') or hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
  public ResponseEntity<?> updateUserPreferences(@Valid @RequestBody UserPreferencesDto preferencesDto) {
    try {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      String username = authentication.getName();
      
      UserPreferencesDto updated = preferencesService.updateUserPreferences(username, preferencesDto);
      return ResponseEntity.ok(updated);
    } catch (Exception e) {
      return ResponseEntity.badRequest()
              .body(ApiError.builder()
                      .status(400)
                      .message("Error: " + e.getMessage())
                      .timestamp(java.time.LocalDateTime.now())
                      .build());
    }
  }

  // Helper method to convert User entity to a safe UserDto
  private UserDto convertToDto(com.techtorque.auth_service.entity.User user) {
    return UserDto.builder()
            .id(user.getId())
            .username(user.getUsername())
            .email(user.getEmail())
            .enabled(user.getEnabled())
            .createdAt(user.getCreatedAt())
            .roles(userService.getUserRoles(user.getUsername()))
            .permissions(userService.getUserPermissions(user.getUsername()))
            .build();
  }
}