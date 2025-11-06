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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.beans.factory.annotation.Value;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import jakarta.servlet.http.HttpServletRequest;

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

    @Autowired
    private com.techtorque.auth_service.repository.LoginLockRepository loginLockRepository;

    @Autowired
    private com.techtorque.auth_service.repository.LoginLogRepository loginLogRepository;

    @Autowired
    private LoginAuditService loginAuditService;

        @Value("${security.login.max-failed-attempts:3}")
        private int maxFailedAttempts;

        // duration in minutes
        @Value("${security.login.lock-duration-minutes:15}")
        private long lockDurationMinutes;
    
    public LoginResponse authenticateUser(LoginRequest loginRequest, HttpServletRequest request) {
        String uname = loginRequest.getUsername();

    // load or create lock record
    com.techtorque.auth_service.entity.LoginLock lock = loginLockRepository.findByUsername(uname)
        .orElseGet(() -> com.techtorque.auth_service.entity.LoginLock.builder().username(uname).failedAttempts(0).build());

        if (lock.getLockUntil() != null && lock.getLockUntil().isAfter(LocalDateTime.now())) {
            long minutesLeft = ChronoUnit.MINUTES.between(LocalDateTime.now(), lock.getLockUntil());
        // record login log using audit service
        String ip = request != null ? (request.getHeader("X-Forwarded-For") == null ? request.getRemoteAddr() : request.getHeader("X-Forwarded-For")) : null;
        String ua = request != null ? request.getHeader("User-Agent") : null;
        loginAuditService.recordLogin(uname, false, ip, ua);
            throw new org.springframework.security.authentication.BadCredentialsException(
                    "Account is temporarily locked. Try again in " + minutesLeft + " minutes.");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            // Successful authentication -> reset failed attempts on lock record
            lock.setFailedAttempts(0);
            lock.setLockUntil(null);
            loginLockRepository.save(lock);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(auth -> auth.replace("ROLE_", ""))
                    .collect(Collectors.toList());

            String jwt = jwtUtil.generateJwtToken(userDetails, roles);

            User foundUser = userRepository.findByUsername(userDetails.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            Set<String> roleNames = foundUser.getRoles().stream()
                    .map(role -> role.getName().name())
                    .collect(Collectors.toSet());

            recordLogin(uname, true, request);

            return LoginResponse.builder()
                    .token(jwt)
                    .username(foundUser.getUsername())
                    .email(foundUser.getEmail())
                    .roles(roleNames)
                    .build();

        } catch (BadCredentialsException ex) {
            // increment failed attempts and possibly lock the user using separate transaction
            loginAuditService.incrementFailedAttempt(uname, lockDurationMinutes, maxFailedAttempts);

            String ip = request != null ? (request.getHeader("X-Forwarded-For") == null ? request.getRemoteAddr() : request.getHeader("X-Forwarded-For")) : null;
            String ua = request != null ? request.getHeader("User-Agent") : null;
            loginAuditService.recordLogin(uname, false, ip, ua);

            throw new org.springframework.security.authentication.BadCredentialsException("Invalid username or password");
        }
    }

    private void recordLogin(String username, boolean success, HttpServletRequest request) {
        String ip = null;
        String ua = null;
        if (request != null) {
            ip = request.getHeader("X-Forwarded-For");
            if (ip == null) ip = request.getRemoteAddr();
            ua = request.getHeader("User-Agent");
        }
        com.techtorque.auth_service.entity.LoginLog log = com.techtorque.auth_service.entity.LoginLog.builder()
                .username(username)
                .success(success)
                .ipAddress(ip)
                .userAgent(ua)
                .createdAt(LocalDateTime.now())
                .build();
        loginLogRepository.save(log);
    }
    
    public String registerUser(RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new com.techtorque.auth_service.exception.DuplicateUserException("Username already exists");
        }

        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new com.techtorque.auth_service.exception.DuplicateUserException("Email already exists");
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