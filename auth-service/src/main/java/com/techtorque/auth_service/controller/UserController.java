package com.techtorque.auth_service.controller;

import com.techtorque.auth_service.dto.UserDto;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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