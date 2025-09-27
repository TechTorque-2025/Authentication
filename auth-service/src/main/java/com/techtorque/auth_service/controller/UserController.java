package com.techtorque.auth_service.controller;

import com.techtorque.auth_service.dto.*;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

/**
 * REST Controller for user management endpoints.
 * Endpoints in this controller are accessible to users with ADMIN or SUPER_ADMIN roles.
 */
@RestController
@RequestMapping("/api/v1/users")
@CrossOrigin(origins = "*", maxAge = 3600)
@PreAuthorize("hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
public class UserController {

  @Autowired
  private UserService userService;

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
      return ResponseEntity.ok(new AuthController.MessageResponse("User '" + username + "' has been disabled."));
    } catch (RuntimeException e) {
      return ResponseEntity.notFound().build();
    }
  }

  /**
   * Enable a user's account.
   */
  @PostMapping("/{username}/enable")
  public ResponseEntity<?> enableUser(@PathVariable String username) {
    try {
      userService.enableUser(username);
      return ResponseEntity.ok(new AuthController.MessageResponse("User '" + username + "' has been enabled."));
    } catch (RuntimeException e) {
      return ResponseEntity.notFound().build();
    }
  }

  /**
   * Delete a user from the system permanently.
   */
  @DeleteMapping("/{username}")
  public ResponseEntity<?> deleteUser(@PathVariable String username) {
    try {
      userService.deleteUser(username);
      return ResponseEntity.ok(new AuthController.MessageResponse("User '" + username + "' has been deleted."));
    } catch (RuntimeException e) {
      return ResponseEntity.notFound().build();
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
      return ResponseEntity.badRequest()
              .body(new AuthController.MessageResponse("Error: " + e.getMessage()));
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
      return ResponseEntity.ok(new AuthController.MessageResponse("Password reset successfully for user: " + username));
    } catch (RuntimeException e) {
      return ResponseEntity.badRequest()
              .body(new AuthController.MessageResponse("Error: " + e.getMessage()));
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
        return ResponseEntity.ok(new AuthController.MessageResponse(
            "Role '" + roleRequest.getRoleName() + "' assigned to user: " + username));
      } else {
        userService.revokeRoleFromUser(username, roleRequest.getRoleName());
        return ResponseEntity.ok(new AuthController.MessageResponse(
            "Role '" + roleRequest.getRoleName() + "' revoked from user: " + username));
      }
    } catch (RuntimeException e) {
      return ResponseEntity.badRequest()
              .body(new AuthController.MessageResponse("Error: " + e.getMessage()));
    }
  }

  /**
   * Get current user's profile (user endpoint)
   * GET /api/v1/users/me
   */
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
              .body(new AuthController.MessageResponse("Error: " + e.getMessage()));
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
      return ResponseEntity.ok(new AuthController.MessageResponse("Password changed successfully"));
    } catch (RuntimeException e) {
      return ResponseEntity.badRequest()
              .body(new AuthController.MessageResponse("Error: " + e.getMessage()));
    }
  }

  // Helper method to convert User entity to a safe UserDto
  private UserDto convertToDto(User user) {
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