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
    
    public LoginResponse authenticateUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );
        
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(auth -> auth.replace("ROLE_", ""))
                .collect(Collectors.toList());
        
        String jwt = jwtUtil.generateJwtToken(userDetails, roles);
        
        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        Set<String> roleNames = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet());
        
        return LoginResponse.builder()
                .token(jwt)
                .username(user.getUsername())
                .email(user.getEmail()) // This was missing in the error
                .roles(roleNames)
                .build();
    }
    
    public String registerUser(RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new RuntimeException("Error: Username is already taken!");
        }
        
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new RuntimeException("Error: Email is already in use!");
        }
        
        User user = User.builder()
                .username(registerRequest.getUsername())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .enabled(true)
                .roles(new HashSet<>())
                .build();
        
        Set<String> strRoles = registerRequest.getRoles();
        Set<Role> roles = new HashSet<>();
        
        if (strRoles == null || strRoles.isEmpty()) {
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