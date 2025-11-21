package com.techtorque.auth_service.service;

import com.techtorque.auth_service.dto.request.LoginRequest;
import com.techtorque.auth_service.dto.request.RegisterRequest;
import com.techtorque.auth_service.dto.response.LoginResponse;
import com.techtorque.auth_service.entity.*;
import com.techtorque.auth_service.repository.*;
import com.techtorque.auth_service.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive test class for AuthService
 * Tests authentication, registration, token management, and security features
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private LoginLockRepository loginLockRepository;

    @Mock
    private LoginLogRepository loginLogRepository;

    @Mock
    private LoginAuditService loginAuditService;

    @Mock
    private TokenService tokenService;

    @Mock
    private EmailService emailService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private Authentication authentication;

    @Mock
    private UserDetails userDetails;

    @InjectMocks
    private AuthService authService;

    private User testUser;
    private Role customerRole;
    private Role adminRole;
    private LoginRequest loginRequest;
    private RegisterRequest registerRequest;
    private LoginLock loginLock;
    private VerificationToken verificationToken;
    private RefreshToken refreshToken;

    @BeforeEach
    void setUp() {
        // Set up test configuration
        ReflectionTestUtils.setField(authService, "maxFailedAttempts", 3);
        ReflectionTestUtils.setField(authService, "lockDurationMinutes", 15L);

        // Create test roles
        customerRole = Role.builder()
                .id("role-1")
                .name(RoleName.CUSTOMER)
                .description("Customer role")
                .build();

        adminRole = Role.builder()
                .id("role-2")
                .name(RoleName.ADMIN)
                .description("Admin role")
                .build();

        // Create test user
        testUser = User.builder()
                .id("user-1")
                .username("testuser")
                .email("test@example.com")
                .password("encoded-password")
                .fullName("Test User")
                .phone("1234567890")
                .address("Test Address")
                .enabled(true)
                .emailVerified(true)
                .createdAt(LocalDateTime.now())
                .roles(Set.of(customerRole))
                .build();

        // Create test requests
        loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password");

        registerRequest = new RegisterRequest();
        registerRequest.setEmail("new@example.com");
        registerRequest.setPassword("newpassword");
        registerRequest.setFullName("New User");
        registerRequest.setPhone("9876543210");
        registerRequest.setAddress("New Address");

        // Create test login lock
        loginLock = LoginLock.builder()
                .id("lock-1")
                .username("testuser")
                .failedAttempts(0)
                .lockUntil(null)
                .build();

        // Create test verification token
        verificationToken = VerificationToken.builder()
                .id("token-1")
                .token("verification-token")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .expiryDate(LocalDateTime.now().plusHours(24))
                .createdAt(LocalDateTime.now())
                .build();

        // Create test refresh token
        refreshToken = RefreshToken.builder()
                .id("refresh-1")
                .token("refresh-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .createdAt(LocalDateTime.now())
                .build();
    }

    @Test
    void authenticateUser_WhenValidCredentials_ShouldReturnLoginResponse() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(loginLockRepository.findByUsername("testuser")).thenReturn(Optional.of(loginLock));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn("testuser");
        when(userDetails.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_CUSTOMER")));
        when(jwtUtil.generateJwtToken(eq(userDetails), anyList())).thenReturn("jwt-token");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(tokenService.createRefreshToken(eq(testUser), anyString(), anyString())).thenReturn("refresh-token");
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getHeader("User-Agent")).thenReturn("Test-Agent");

        // When
        LoginResponse response = authService.authenticateUser(loginRequest, request);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo("jwt-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
        assertThat(response.getUsername()).isEqualTo("testuser");
        assertThat(response.getEmail()).isEqualTo("test@example.com");
        assertThat(response.getRoles()).contains("CUSTOMER");

        verify(loginLockRepository).save(any(LoginLock.class));
        verify(loginLogRepository).save(any(LoginLog.class));
    }

    @Test
    void authenticateUser_WhenUserNotFound_ShouldCheckByEmail() {
        // Given
        when(userRepository.findByUsername("test@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(loginLockRepository.findByUsername("test@example.com")).thenReturn(Optional.of(loginLock));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn("test@example.com");
        when(userDetails.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_CUSTOMER")));

        loginRequest.setUsername("test@example.com");

        // When/Then
        when(jwtUtil.generateJwtToken(eq(userDetails), anyList())).thenReturn("jwt-token");
        when(userRepository.findByUsername("test@example.com")).thenReturn(Optional.of(testUser));
        when(tokenService.createRefreshToken(eq(testUser), anyString(), anyString())).thenReturn("refresh-token");

        LoginResponse response = authService.authenticateUser(loginRequest, request);
        assertThat(response).isNotNull();
    }

    @Test
    void authenticateUser_WhenUserDisabledAndNotVerified_ShouldThrowDisabledException() {
        // Given
        testUser.setEnabled(false);
        testUser.setEmailVerified(false);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When/Then
        assertThatThrownBy(() -> authService.authenticateUser(loginRequest, request))
                .isInstanceOf(DisabledException.class)
                .hasMessageContaining("Please verify your email address");
    }

    @Test
    void authenticateUser_WhenUserDisabledAndVerified_ShouldThrowDisabledException() {
        // Given
        testUser.setEnabled(false);
        testUser.setEmailVerified(true);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When/Then
        assertThatThrownBy(() -> authService.authenticateUser(loginRequest, request))
                .isInstanceOf(DisabledException.class)
                .hasMessageContaining("Your account has been deactivated");
    }

    @Test
    void authenticateUser_WhenAccountLocked_ShouldThrowBadCredentialsException() {
        // Given
        loginLock.setLockUntil(LocalDateTime.now().plusMinutes(10));
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(loginLockRepository.findByUsername("testuser")).thenReturn(Optional.of(loginLock));

        // When/Then
        assertThatThrownBy(() -> authService.authenticateUser(loginRequest, request))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("Account is temporarily locked");

        verify(loginAuditService).recordLogin(eq("testuser"), eq(false), anyString(), anyString());
    }

    @Test
    void authenticateUser_WhenNoLockRecord_ShouldCreateNewLock() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(loginLockRepository.findByUsername("testuser")).thenReturn(Optional.empty());
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn("testuser");
        when(userDetails.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_CUSTOMER")));
        when(jwtUtil.generateJwtToken(eq(userDetails), anyList())).thenReturn("jwt-token");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(tokenService.createRefreshToken(eq(testUser), anyString(), anyString())).thenReturn("refresh-token");

        // When
        LoginResponse response = authService.authenticateUser(loginRequest, request);

        // Then
        assertThat(response).isNotNull();
        verify(loginLockRepository)
                .save(argThat(lock -> lock.getUsername().equals("testuser") && lock.getFailedAttempts() == 0));
    }

    @Test
    void authenticateUser_WhenBadCredentials_ShouldIncrementFailedAttempts() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(loginLockRepository.findByUsername("testuser")).thenReturn(Optional.of(loginLock));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // When/Then
        assertThatThrownBy(() -> authService.authenticateUser(loginRequest, request))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Invalid username or password");

        verify(loginAuditService).incrementFailedAttempt("testuser", 15L, 3);
        verify(loginAuditService).recordLogin(eq("testuser"), eq(false), anyString(), anyString());
    }

    @Test
    void registerUser_WhenValidRequest_ShouldCreateUserAndSendVerificationEmail() {
        // Given
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(roleRepository.findByName(RoleName.CUSTOMER)).thenReturn(Optional.of(customerRole));
        when(passwordEncoder.encode("newpassword")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(tokenService.createVerificationToken(any(User.class))).thenReturn("verification-token");

        // When
        String result = authService.registerUser(registerRequest);

        // Then
        assertThat(result).contains("User registered successfully");
        verify(userRepository).save(argThat(user -> user.getEmail().equals("new@example.com") &&
                user.getFullName().equals("New User") &&
                !user.getEnabled() &&
                !user.getEmailVerified()));
        verify(emailService).sendVerificationEmail("new@example.com", "new@example.com", "verification-token");
    }

    @Test
    void registerUser_WhenEmailExists_ShouldThrowRuntimeException() {
        // Given
        when(userRepository.existsByEmail("new@example.com")).thenReturn(true);

        // When/Then
        assertThatThrownBy(() -> authService.registerUser(registerRequest))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Error: Email is already in use!");
    }

    @Test
    void registerUser_WhenAdminRole_ShouldAssignAdminRole() {
        // Given
        registerRequest.setRoles(Set.of("admin"));
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(roleRepository.findByName(RoleName.ADMIN)).thenReturn(Optional.of(adminRole));
        when(passwordEncoder.encode("newpassword")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(tokenService.createVerificationToken(any(User.class))).thenReturn("verification-token");

        // When
        authService.registerUser(registerRequest);

        // Then
        verify(roleRepository).findByName(RoleName.ADMIN);
        verify(userRepository).save(argThat(user -> user.getRoles().contains(adminRole)));
    }

    @Test
    void registerUser_WhenEmployeeRole_ShouldAssignEmployeeRole() {
        // Given
        Role employeeRole = Role.builder().id("role-3").name(RoleName.EMPLOYEE).build();
        registerRequest.setRoles(Set.of("employee"));
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(roleRepository.findByName(RoleName.EMPLOYEE)).thenReturn(Optional.of(employeeRole));
        when(passwordEncoder.encode("newpassword")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(tokenService.createVerificationToken(any(User.class))).thenReturn("verification-token");

        // When
        authService.registerUser(registerRequest);

        // Then
        verify(roleRepository).findByName(RoleName.EMPLOYEE);
        verify(userRepository).save(argThat(user -> user.getRoles().contains(employeeRole)));
    }

    @Test
    void registerUser_WhenInvalidRole_ShouldAssignCustomerRole() {
        // Given
        registerRequest.setRoles(Set.of("invalid"));
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(roleRepository.findByName(RoleName.CUSTOMER)).thenReturn(Optional.of(customerRole));
        when(passwordEncoder.encode("newpassword")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(tokenService.createVerificationToken(any(User.class))).thenReturn("verification-token");

        // When
        authService.registerUser(registerRequest);

        // Then
        verify(roleRepository).findByName(RoleName.CUSTOMER);
        verify(userRepository).save(argThat(user -> user.getRoles().contains(customerRole)));
    }

    @Test
    void registerUser_WhenRoleNotFound_ShouldThrowRuntimeException() {
        // Given
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(roleRepository.findByName(RoleName.CUSTOMER)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("newpassword")).thenReturn("encoded-password");

        // When/Then
        assertThatThrownBy(() -> authService.registerUser(registerRequest))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Error: Customer Role not found.");
    }

    @Test
    void verifyEmail_WhenValidToken_ShouldEnableUserAndReturnLoginResponse() {
        // Given
        testUser.setEnabled(false);
        testUser.setEmailVerified(false);
        when(tokenService.validateToken("verification-token", VerificationToken.TokenType.EMAIL_VERIFICATION))
                .thenReturn(verificationToken);
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(jwtUtil.generateJwtToken(any(UserDetails.class), anyList())).thenReturn("jwt-token");
        when(tokenService.createRefreshToken(eq(testUser), anyString(), anyString())).thenReturn("refresh-token");

        // When
        LoginResponse response = authService.verifyEmail("verification-token", request);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo("jwt-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
        verify(userRepository).save(argThat(user -> user.getEnabled() && user.getEmailVerified()));
        verify(tokenService).markTokenAsUsed(verificationToken);
        verify(emailService).sendWelcomeEmail("test@example.com", "testuser");
    }

    @Test
    void resendVerificationEmail_WhenUserExists_ShouldSendEmail() {
        // Given
        testUser.setEmailVerified(false);
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(tokenService.createVerificationToken(testUser)).thenReturn("new-verification-token");

        // When
        String result = authService.resendVerificationEmail("test@example.com");

        // Then
        assertThat(result).contains("Verification email sent successfully");
        verify(emailService).sendVerificationEmail("test@example.com", "testuser", "new-verification-token");
    }

    @Test
    void resendVerificationEmail_WhenUserNotFound_ShouldThrowRuntimeException() {
        // Given
        when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

        // When/Then
        assertThatThrownBy(() -> authService.resendVerificationEmail("nonexistent@example.com"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("User not found with email: nonexistent@example.com");
    }

    @Test
    void resendVerificationEmail_WhenEmailAlreadyVerified_ShouldThrowRuntimeException() {
        // Given
        testUser.setEmailVerified(true);
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        // When/Then
        assertThatThrownBy(() -> authService.resendVerificationEmail("test@example.com"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Email is already verified");
    }

    @Test
    void refreshToken_WhenValidToken_ShouldReturnNewLoginResponse() {
        // Given
        when(tokenService.validateRefreshToken("refresh-token")).thenReturn(refreshToken);
        when(jwtUtil.generateJwtToken(any(UserDetails.class), anyList())).thenReturn("new-jwt-token");

        // When
        LoginResponse response = authService.refreshToken("refresh-token");

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo("new-jwt-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
        assertThat(response.getUsername()).isEqualTo("testuser");
        assertThat(response.getEmail()).isEqualTo("test@example.com");
    }

    @Test
    void logout_ShouldRevokeRefreshToken() {
        // When
        authService.logout("refresh-token");

        // Then
        verify(tokenService).revokeRefreshToken("refresh-token");
    }

    @Test
    void forgotPassword_WhenUserExists_ShouldSendResetEmail() {
        // Given
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(tokenService.createPasswordResetToken(testUser)).thenReturn("reset-token");

        // When
        String result = authService.forgotPassword("test@example.com");

        // Then
        assertThat(result).contains("Password reset email sent successfully");
        verify(emailService).sendPasswordResetEmail("test@example.com", "testuser", "reset-token");
    }

    @Test
    void forgotPassword_WhenUserNotFound_ShouldThrowRuntimeException() {
        // Given
        when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

        // When/Then
        assertThatThrownBy(() -> authService.forgotPassword("nonexistent@example.com"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("User not found with email: nonexistent@example.com");
    }

    @Test
    void resetPassword_WhenValidToken_ShouldUpdatePasswordAndRevokeTokens() {
        // Given
        VerificationToken resetToken = VerificationToken.builder()
                .token("reset-token")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .build();

        when(tokenService.validateToken("reset-token", VerificationToken.TokenType.PASSWORD_RESET))
                .thenReturn(resetToken);
        when(passwordEncoder.encode("newpassword")).thenReturn("new-encoded-password");
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        String result = authService.resetPassword("reset-token", "newpassword");

        // Then
        assertThat(result).contains("Password reset successfully");
        verify(userRepository).save(argThat(user -> user.getPassword().equals("new-encoded-password")));
        verify(tokenService).markTokenAsUsed(resetToken);
        verify(tokenService).revokeAllUserTokens(testUser);
    }

    @Test
    void authenticateUser_WhenNullRequest_ShouldHandleGracefully() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(loginLockRepository.findByUsername("testuser")).thenReturn(Optional.of(loginLock));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn("testuser");
        when(userDetails.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_CUSTOMER")));
        when(jwtUtil.generateJwtToken(eq(userDetails), anyList())).thenReturn("jwt-token");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(tokenService.createRefreshToken(eq(testUser), isNull(), isNull())).thenReturn("refresh-token");

        // When
        LoginResponse response = authService.authenticateUser(loginRequest, null);

        // Then
        assertThat(response).isNotNull();
        verify(tokenService).createRefreshToken(eq(testUser), isNull(), isNull());
    }

    @Test
    void verifyEmail_WhenNullRequest_ShouldHandleGracefully() {
        // Given
        testUser.setEnabled(false);
        testUser.setEmailVerified(false);
        when(tokenService.validateToken("verification-token", VerificationToken.TokenType.EMAIL_VERIFICATION))
                .thenReturn(verificationToken);
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(jwtUtil.generateJwtToken(any(UserDetails.class), anyList())).thenReturn("jwt-token");
        when(tokenService.createRefreshToken(eq(testUser), isNull(), isNull())).thenReturn("refresh-token");

        // When
        LoginResponse response = authService.verifyEmail("verification-token", null);

        // Then
        assertThat(response).isNotNull();
        verify(tokenService).createRefreshToken(eq(testUser), isNull(), isNull());
    }
}