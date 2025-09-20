package com.techtorque.authservice.controller;

import com.techtorque.authservice.service.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

// Define request and response structures
record LoginRequest(String username, String password) {}
record LoginResponse(String token) {}

@RestController
public class AuthController {

  @Autowired
  private JwtUtil jwtUtil;

  @PostMapping("/login")
  public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
    // --- FAKE USER AUTHENTICATION ---
    // In a real application, you would check the username and password against a database.
    // For this assignment, we will hardcode a user.
    if ("user".equals(request.username()) && "password".equals(request.password())) {
      String token = jwtUtil.generateToken(request.username());
      return ResponseEntity.ok(new LoginResponse(token));
    } else {
      // If authentication fails, return 401 Unauthorized
      return ResponseEntity.status(401).build();
    }
  }
}