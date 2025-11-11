package com.techtorque.auth_service.service;

import com.techtorque.auth_service.dto.request.LoginRequest;
import com.techtorque.auth_service.dto.response.LoginResponse;
import com.techtorque.auth_service.dto.request.RegisterRequest;
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

    @Autowired
    private TokenService tokenService;

    @Autowired
    private EmailService emailService;

        @Value("${security.login.max-failed-attempts:3}")
        private int maxFailedAttempts;

        // duration in minutes
        @Value("${security.login.lock-duration-minutes:15}")
        private long lockDurationMinutes;
    
    public LoginResponse authenticateUser(LoginRequest loginRequest, HttpServletRequest request) {
        String uname = loginRequest.getUsername();

        // Check if user exists and is not verified
        java.util.Optional<User> userOpt = userRepository.findByUsername(uname);
        if (userOpt.isEmpty()) {
            userOpt = userRepository.findByEmail(uname);
        }
        
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            
            // Check if account is disabled (deactivated by admin)
            if (!user.getEnabled()) {
                if (!user.getEmailVerified()) {
                    throw new org.springframework.security.authentication.DisabledException(
                        "Please verify your email address before logging in. Check your inbox for the verification link.");
                } else {
                    throw new org.springframework.security.authentication.DisabledException(
                        "Your account has been deactivated. Please contact the administrator for assistance.");
                }
            }
        }

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
            
            // Create refresh token
            String ip = request != null ? (request.getHeader("X-Forwarded-For") == null ? request.getRemoteAddr() : request.getHeader("X-Forwarded-For")) : null;
            String ua = request != null ? request.getHeader("User-Agent") : null;
            String refreshToken = tokenService.createRefreshToken(foundUser, ip, ua);

            return LoginResponse.builder()
                    .token(jwt)
                    .refreshToken(refreshToken)
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
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new RuntimeException("Error: Email is already in use!");
        }
        
        User user = User.builder()
                .username(registerRequest.getEmail()) // Use email as username for simplicity
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .fullName(registerRequest.getFullName())
                .phone(registerRequest.getPhone())
                .address(registerRequest.getAddress())
                .enabled(false) // Require email verification before login
                .emailVerified(false) // Track verification status separately
                .emailVerificationDeadline(LocalDateTime.now().plus(7, ChronoUnit.DAYS)) // 1 week deadline
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
        User savedUser = userRepository.save(user);
        
        // Create verification token and send email
        String token = tokenService.createVerificationToken(savedUser);
        emailService.sendVerificationEmail(savedUser.getEmail(), savedUser.getUsername(), token);
        
        return "User registered successfully! Please check your email to verify your account.";
    }
    
    /**
     * Verify email with token
     */
    public LoginResponse verifyEmail(String token, HttpServletRequest request) {
        com.techtorque.auth_service.entity.VerificationToken verificationToken = 
                tokenService.validateToken(token, com.techtorque.auth_service.entity.VerificationToken.TokenType.EMAIL_VERIFICATION);
        
        User user = verificationToken.getUser();
        user.setEnabled(true);
        user.setEmailVerified(true); // Mark email as verified
        User updatedUser = userRepository.save(user);

        tokenService.markTokenAsUsed(verificationToken);
        
        // Send welcome email
        emailService.sendWelcomeEmail(updatedUser.getEmail(), updatedUser.getUsername());

        // Auto-login after verification
        Set<String> roleNames = updatedUser.getRoles() != null ?
            updatedUser.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet()) :
            Set.of("CUSTOMER");

        List<String> roles = new java.util.ArrayList<>(roleNames);

        Set<org.springframework.security.core.authority.SimpleGrantedAuthority> authorities = new java.util.HashSet<>();
        if (updatedUser.getRoles() != null) {
            updatedUser.getRoles().stream()
                .flatMap(role -> role.getPermissions() != null ? role.getPermissions().stream() : java.util.stream.Stream.empty())
                .forEach(permission -> authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority(permission.getName())));
        }

        String jwt = jwtUtil.generateJwtToken(new org.springframework.security.core.userdetails.User(
                updatedUser.getUsername(),
                updatedUser.getPassword(),
                authorities
        ), roles);
        
        String ip = request != null ? (request.getHeader("X-Forwarded-For") == null ? request.getRemoteAddr() : request.getHeader("X-Forwarded-For")) : null;
        String ua = request != null ? request.getHeader("User-Agent") : null;
        String refreshToken = tokenService.createRefreshToken(updatedUser, ip, ua);

        return LoginResponse.builder()
                .token(jwt)
                .refreshToken(refreshToken)
                .username(updatedUser.getUsername())
                .email(updatedUser.getEmail())
                .roles(roleNames)
                .build();
    }
    
    /**
     * Resend verification email
     */
    public String resendVerificationEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
        
        if (user.getEmailVerified()) {
            throw new RuntimeException("Email is already verified");
        }
        
        String token = tokenService.createVerificationToken(user);
        emailService.sendVerificationEmail(user.getEmail(), user.getUsername(), token);
        
        return "Verification email sent successfully!";
    }
    
    /**
     * Refresh JWT token
     */
    public LoginResponse refreshToken(String refreshTokenString) {
        com.techtorque.auth_service.entity.RefreshToken refreshToken = tokenService.validateRefreshToken(refreshTokenString);
        
        User user = refreshToken.getUser();

        List<String> roles = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList());

        String jwt = jwtUtil.generateJwtToken(new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getRoles().stream()
                        .flatMap(role -> role.getPermissions().stream())
                        .map(permission -> new org.springframework.security.core.authority.SimpleGrantedAuthority(permission.getName()))
                        .collect(Collectors.toSet())
        ), roles);
        
        Set<String> roleNames = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet());
        
        return LoginResponse.builder()
                .token(jwt)
                .refreshToken(refreshTokenString) // Return same refresh token
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(roleNames)
                .build();
    }
    
    /**
     * Logout - revoke refresh token
     */
    public void logout(String refreshToken) {
        tokenService.revokeRefreshToken(refreshToken);
    }
    
    /**
     * Request password reset
     */
    public String forgotPassword(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
        
        String token = tokenService.createPasswordResetToken(user);
        emailService.sendPasswordResetEmail(user.getEmail(), user.getUsername(), token);
        
        return "Password reset email sent successfully!";
    }
    
    /**
     * Reset password with token
     */
    public String resetPassword(String token, String newPassword) {
        com.techtorque.auth_service.entity.VerificationToken resetToken = 
                tokenService.validateToken(token, com.techtorque.auth_service.entity.VerificationToken.TokenType.PASSWORD_RESET);
        
        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        
        tokenService.markTokenAsUsed(resetToken);
        
        // Revoke all existing refresh tokens for security
        tokenService.revokeAllUserTokens(user);
        
        return "Password reset successfully!";
    }
}
