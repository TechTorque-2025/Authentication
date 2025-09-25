package com.techtorque.auth_service.service;

import com.techtorque.auth_service.dto.LoginRequest;
import com.techtorque.auth_service.dto.LoginResponse;
import com.techtorque.auth_service.dto.RegisterRequest;
import com.techtorque.auth_service.entity.Role;
import com.techtorque.auth_service.entity.RoleName;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.repository.RoleRepository;
import com.techtorque.auth_service.repository.UserRepository;
import com.techtorque.auth_service.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service class for handling authentication operations
 * Manages user login, registration, and JWT token generation
 */
@Service
@Transactional
public class AuthService {
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private JwtUtil jwtUtil;
    
    /**
     * Authenticate user and generate JWT token
     * @param loginRequest Login credentials
     * @return LoginResponse with JWT token and user details
     */
    public LoginResponse authenticateUser(LoginRequest loginRequest) {
        // Authenticate user credentials
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );
        
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        
        // Extract roles from authorities
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(auth -> auth.replace("ROLE_", "")) // Remove ROLE_ prefix
                .collect(Collectors.toList());
        
        // Generate JWT token
        String jwt = jwtUtil.generateJwtToken(userDetails, roles);
        
        // Get user details for response
        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        Set<String> roleNames = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet());
        
        return LoginResponse.builder()
                .token(jwt)
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(roleNames)
                .build();
    }
    
    /**
     * Register a new user with specified roles
     * @param registerRequest Registration details
     * @return Success message
     */
    public String registerUser(RegisterRequest registerRequest) {
        // Check if username already exists
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new RuntimeException("Error: Username is already taken!");
        }
        
        // Check if email already exists
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new RuntimeException("Error: Email is already in use!");
        }
        
        // Create new user
        User user = User.builder()
                .username(registerRequest.getUsername())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .enabled(true)
                .roles(new HashSet<>())
                .build();
        
        // Assign roles
        Set<String> strRoles = registerRequest.getRoles();
        Set<Role> roles = new HashSet<>();
        
        if (strRoles == null || strRoles.isEmpty()) {
            // Default role is CUSTOMER
            Role customerRole = roleRepository.findByName(RoleName.CUSTOMER)
                    .orElseThrow(() -> new RuntimeException("Error: Customer Role not found."));
            roles.add(customerRole);
        } else {
            strRoles.forEach(roleName -> {
                switch (roleName) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(RoleName.ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Admin Role not found."));
                        roles.add(adminRole);
                        break;
                    case "employee":
                        Role employeeRole = roleRepository.findByName(RoleName.EMPLOYEE)
                                .orElseThrow(() -> new RuntimeException("Error: Employee Role not found."));
                        roles.add(employeeRole);
                        break;
                    default:
                        Role customerRole = roleRepository.findByName(RoleName.CUSTOMER)
                                .orElseThrow(() -> new RuntimeException("Error: Customer Role not found."));
                        roles.add(customerRole);
                }
            });
        }
        
        user.setRoles(roles);
        userRepository.save(user);
        
        return "User registered successfully!";
    }
}