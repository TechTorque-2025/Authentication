package com.techtorque.auth_service.service;

import com.techtorque.auth_service.entity.Role;
import com.techtorque.auth_service.entity.RoleName;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.repository.*;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive test class for UserService
 * Tests user management, security, and role/permission operations
 */
@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private LoginLockRepository loginLockRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private VerificationTokenRepository verificationTokenRepository;

    @Mock
    private LoginLogRepository loginLogRepository;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authentication authentication;

    @InjectMocks
    private UserService userService;

    private User testUser;
    private Role customerRole;
    private Role employeeRole;
    private Role adminRole;
    private Role superAdminRole;

    @BeforeEach
    void setUp() {
        // Create test roles
        customerRole = Role.builder()
                .id(1L)
                .name(RoleName.CUSTOMER)
                .description("Customer role")
                .permissions(new HashSet<>())
                .build();

        employeeRole = Role.builder()
                .id(2L)
                .name(RoleName.EMPLOYEE)
                .description("Employee role")
                .permissions(new HashSet<>())
                .build();

        adminRole = Role.builder()
                .id(3L)
                .name(RoleName.ADMIN)
                .description("Admin role")
                .permissions(new HashSet<>())
                .build();

        superAdminRole = Role.builder()
                .id(4L)
                .name(RoleName.SUPER_ADMIN)
                .description("Super Admin role")
                .permissions(new HashSet<>())
                .build();

        // Create test user
        testUser = User.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .password("encoded-password")
                .fullName("Test User")
                .phone("1234567890")
                .address("Test Address")
                .enabled(true)
                .emailVerified(true)
                .roles(new HashSet<>(Set.of(customerRole)))
                .build();
    }

    @Test
    void loadUserByUsername_WhenUserFoundByUsername_ShouldReturnUserDetails() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        UserDetails userDetails = userService.loadUserByUsername("testuser");

        // Then
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo("testuser");
        assertThat(userDetails.getPassword()).isEqualTo("encoded-password");
        assertThat(userDetails.isEnabled()).isTrue();
        assertThat(userDetails.isAccountNonLocked()).isTrue();
        assertThat(userDetails.getAuthorities()).hasSize(1);
        assertThat(userDetails.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_CUSTOMER");
    }

    @Test
    void loadUserByUsername_WhenUserFoundByEmail_ShouldReturnUserDetails() {
        // Given
        when(userRepository.findByUsername("test@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        // When
        UserDetails userDetails = userService.loadUserByUsername("test@example.com");

        // Then
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo("testuser");
        verify(userRepository).findByUsername("test@example.com");
        verify(userRepository).findByEmail("test@example.com");
    }

    @Test
    void loadUserByUsername_WhenUserNotFound_ShouldThrowUsernameNotFoundException() {
        // Given
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("nonexistent")).thenReturn(Optional.empty());

        // When/Then
        assertThatThrownBy(() -> userService.loadUserByUsername("nonexistent"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage("User not found: nonexistent");
    }

    @Test
    void loadUserByUsername_WhenUserDisabled_ShouldReturnDisabledUserDetails() {
        // Given
        testUser.setEnabled(false);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        UserDetails userDetails = userService.loadUserByUsername("testuser");

        // Then
        assertThat(userDetails.isEnabled()).isFalse();
        assertThat(userDetails.isAccountNonLocked()).isFalse();
    }

    @Test
    void registerCustomer_WhenValidInput_ShouldCreateCustomerUser() {
        // Given
        when(userRepository.findByUsername("newuser")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("new@example.com")).thenReturn(Optional.empty());
        when(roleRepository.findByName(RoleName.CUSTOMER)).thenReturn(Optional.of(customerRole));
        when(passwordEncoder.encode("password")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        User result = userService.registerCustomer("newuser", "new@example.com", "password");

        // Then
        assertThat(result).isNotNull();
        verify(userRepository).save(argThat(user -> user.getUsername().equals("newuser") &&
                user.getEmail().equals("new@example.com") &&
                user.getPassword().equals("encoded-password") &&
                user.getEnabled() &&
                user.getRoles().contains(customerRole)));
    }

    @Test
    void registerCustomer_WhenUsernameExists_ShouldThrowIllegalArgumentException() {
        // Given
        when(userRepository.findByUsername("existinguser")).thenReturn(Optional.of(testUser));

        // When/Then
        assertThatThrownBy(() -> userService.registerCustomer("existinguser", "new@example.com", "password"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Username already exists: existinguser");
    }

    @Test
    void registerCustomer_WhenEmailExists_ShouldThrowIllegalArgumentException() {
        // Given
        when(userRepository.findByUsername("newuser")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("existing@example.com")).thenReturn(Optional.of(testUser));

        // When/Then
        assertThatThrownBy(() -> userService.registerCustomer("newuser", "existing@example.com", "password"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Email already exists: existing@example.com");
    }

    @Test
    void registerCustomer_WhenCustomerRoleNotFound_ShouldThrowEntityNotFoundException() {
        // Given
        when(userRepository.findByUsername("newuser")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("new@example.com")).thenReturn(Optional.empty());
        when(roleRepository.findByName(RoleName.CUSTOMER)).thenReturn(Optional.empty());

        // When/Then
        assertThatThrownBy(() -> userService.registerCustomer("newuser", "new@example.com", "password"))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessage("Customer role not found");
    }

    @Test
    void createEmployee_WhenValidInput_ShouldCreateEmployeeUser() {
        // Given
        when(userRepository.findByUsername("employee")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("employee@example.com")).thenReturn(Optional.empty());
        when(roleRepository.findByName(RoleName.EMPLOYEE)).thenReturn(Optional.of(employeeRole));
        when(passwordEncoder.encode("password")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        User result = userService.createEmployee("employee", "employee@example.com", "password");

        // Then
        assertThat(result).isNotNull();
        verify(userRepository).save(argThat(user -> user.getUsername().equals("employee") &&
                user.getEmail().equals("employee@example.com") &&
                user.getRoles().contains(employeeRole)));
    }

    @Test
    void createAdmin_WhenValidInput_ShouldCreateAdminUser() {
        // Given
        when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.empty());
        when(roleRepository.findByName(RoleName.ADMIN)).thenReturn(Optional.of(adminRole));
        when(passwordEncoder.encode("password")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        User result = userService.createAdmin("admin", "admin@example.com", "password");

        // Then
        assertThat(result).isNotNull();
        verify(userRepository).save(argThat(user -> user.getUsername().equals("admin") &&
                user.getEmail().equals("admin@example.com") &&
                user.getRoles().contains(adminRole)));
    }

    @Test
    void findByUsername_WhenUserExists_ShouldReturnUser() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        Optional<User> result = userService.findByUsername("testuser");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get()).isEqualTo(testUser);
    }

    @Test
    void findByEmail_WhenUserExists_ShouldReturnUser() {
        // Given
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        // When
        Optional<User> result = userService.findByEmail("test@example.com");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get()).isEqualTo(testUser);
    }

    @Test
    void findAllUsers_ShouldReturnAllUsers() {
        // Given
        List<User> users = List.of(testUser);
        when(userRepository.findAll()).thenReturn(users);

        // When
        List<User> result = userService.findAllUsers();

        // Then
        assertThat(result).isEqualTo(users);
    }

    @Test
    void getUserPermissions_WhenUserExists_ShouldReturnPermissions() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        Set<String> permissions = userService.getUserPermissions("testuser");

        // Then
        assertThat(permissions).isNotNull();
        // Note: permissions are empty in our test setup, so this just verifies the
        // method works
    }

    @Test
    void getUserPermissions_WhenUserNotFound_ShouldThrowEntityNotFoundException() {
        // Given
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        // When/Then
        assertThatThrownBy(() -> userService.getUserPermissions("nonexistent"))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessage("User not found: nonexistent");
    }

    @Test
    void getUserRoles_WhenUserExists_ShouldReturnRoles() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        Set<String> roles = userService.getUserRoles("testuser");

        // Then
        assertThat(roles).contains("CUSTOMER");
    }

    @Test
    void enableUser_WhenUserExists_ShouldEnableUser() {
        // Given
        testUser.setEnabled(false);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.enableUser("testuser");

        // Then
        assertThat(testUser.getEnabled()).isTrue();
        verify(userRepository).save(testUser);
    }

    @Test
    void disableUser_WhenUserExists_ShouldDisableUser() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.disableUser("testuser");

        // Then
        assertThat(testUser.getEnabled()).isFalse();
        verify(userRepository).save(testUser);
    }

    @Test
    void deleteUser_WhenUserExists_ShouldDeleteUserAndRelatedData() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        userService.deleteUser("testuser");

        // Then
        verify(userRepository).save(testUser); // Clear roles
        verify(refreshTokenRepository).deleteByUser(testUser);
        verify(verificationTokenRepository).deleteByUser(testUser);
        verify(loginLockRepository).deleteByUsername("testuser");
        verify(loginLogRepository).deleteByUsername("testuser");
        verify(userRepository).delete(testUser);
    }

    @Test
    void deleteUser_WhenUserNotFound_ShouldThrowEntityNotFoundException() {
        // Given
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        // When/Then
        assertThatThrownBy(() -> userService.deleteUser("nonexistent"))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessage("User not found: nonexistent");
    }

    @Test
    void clearLoginLock_WhenLockExists_ShouldClearLock() {
        // Given
        com.techtorque.auth_service.entity.LoginLock loginLock = com.techtorque.auth_service.entity.LoginLock.builder()
                .username("testuser")
                .failedAttempts(3)
                .lockUntil(java.time.LocalDateTime.now().plusMinutes(15))
                .build();
        when(loginLockRepository.findByUsername("testuser")).thenReturn(Optional.of(loginLock));

        // When
        userService.clearLoginLock("testuser");

        // Then
        assertThat(loginLock.getFailedAttempts()).isEqualTo(0);
        assertThat(loginLock.getLockUntil()).isNull();
        verify(loginLockRepository).save(loginLock);
    }

    @Test
    void clearLoginLock_WhenLockNotExists_ShouldNotThrowException() {
        // Given
        when(loginLockRepository.findByUsername("testuser")).thenReturn(Optional.empty());

        // When/Then
        assertThatCode(() -> userService.clearLoginLock("testuser"))
                .doesNotThrowAnyException();
    }

    @Test
    void hasRole_WhenUserHasRole_ShouldReturnTrue() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        boolean result = userService.hasRole("testuser", RoleName.CUSTOMER);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void hasRole_WhenUserDoesNotHaveRole_ShouldReturnFalse() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        boolean result = userService.hasRole("testuser", RoleName.ADMIN);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void hasPermission_WhenUserHasPermission_ShouldReturnTrue() {
        // Given
        com.techtorque.auth_service.entity.Permission permission = com.techtorque.auth_service.entity.Permission
                .builder()
                .name("READ_USERS")
                .build();
        customerRole.getPermissions().add(permission);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        boolean result = userService.hasPermission("testuser", "READ_USERS");

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void hasPermission_WhenUserDoesNotHavePermission_ShouldReturnFalse() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        boolean result = userService.hasPermission("testuser", "DELETE_USERS");

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void updateUserDetails_WhenValidInput_ShouldUpdateUser() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(userRepository.existsByUsername("newusername")).thenReturn(false);
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        User result = userService.updateUserDetails("testuser", "newusername", "new@example.com", false);

        // Then
        assertThat(result.getUsername()).isEqualTo("newusername");
        assertThat(result.getEmail()).isEqualTo("new@example.com");
        assertThat(result.getEnabled()).isFalse();
    }

    @Test
    void updateUserDetails_WhenUsernameExists_ShouldThrowIllegalArgumentException() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(userRepository.existsByUsername("existingusername")).thenReturn(true);

        // When/Then
        assertThatThrownBy(() -> userService.updateUserDetails("testuser", "existingusername", null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Username already exists: existingusername");
    }

    @Test
    void resetUserPassword_WhenUserExists_ShouldUpdatePassword() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.encode("newpassword")).thenReturn("new-encoded-password");
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.resetUserPassword("testuser", "newpassword");

        // Then
        assertThat(testUser.getPassword()).isEqualTo("new-encoded-password");
        verify(userRepository).save(testUser);
    }

    @Test
    void changeUserPassword_WhenCurrentPasswordCorrect_ShouldUpdatePassword() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("currentpassword", "encoded-password")).thenReturn(true);
        when(passwordEncoder.encode("newpassword")).thenReturn("new-encoded-password");
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.changeUserPassword("testuser", "currentpassword", "newpassword");

        // Then
        assertThat(testUser.getPassword()).isEqualTo("new-encoded-password");
        verify(userRepository).save(testUser);
    }

    @Test
    void changeUserPassword_WhenCurrentPasswordIncorrect_ShouldThrowIllegalStateException() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrongpassword", "encoded-password")).thenReturn(false);

        // When/Then
        assertThatThrownBy(() -> userService.changeUserPassword("testuser", "wrongpassword", "newpassword"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Current password is incorrect");
    }

    @Test
    void assignRoleToUser_WhenValidRole_ShouldAssignRole() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(roleRepository.findByName(RoleName.EMPLOYEE)).thenReturn(Optional.of(employeeRole));
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.assignRoleToUser("testuser", "EMPLOYEE");

        // Then
        assertThat(testUser.getRoles()).contains(employeeRole);
        verify(userRepository).save(testUser);
    }

    @Test
    void assignRoleToUser_WhenAssigningAdminRoleWithoutSuperAdminAuth_ShouldThrowAccessDeniedException() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(roleRepository.findByName(RoleName.ADMIN)).thenReturn(Optional.of(adminRole));

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getAuthorities()).thenReturn((Collection) java.util.Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN")));

        // When/Then
        assertThatThrownBy(() -> userService.assignRoleToUser("testuser", "ADMIN"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Permission denied: Only a SUPER_ADMIN can assign the ADMIN role.");

        SecurityContextHolder.clearContext();
    }

    @Test
    void assignRoleToUser_WhenAssigningAdminRoleWithSuperAdminAuth_ShouldSucceed() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(roleRepository.findByName(RoleName.ADMIN)).thenReturn(Optional.of(adminRole));
        when(userRepository.save(testUser)).thenReturn(testUser);

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getAuthorities()).thenReturn((Collection) java.util.Collections.singletonList(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));

        // When
        userService.assignRoleToUser("testuser", "ADMIN");

        // Then
        assertThat(testUser.getRoles()).contains(adminRole);
        verify(userRepository).save(testUser);
        SecurityContextHolder.clearContext();
    }

    @Test
    void assignRoleToUser_WhenRoleAlreadyAssigned_ShouldThrowIllegalStateException() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(roleRepository.findByName(RoleName.CUSTOMER)).thenReturn(Optional.of(customerRole));

        // When/Then
        assertThatThrownBy(() -> userService.assignRoleToUser("testuser", "CUSTOMER"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("User already has role: CUSTOMER");
    }

    @Test
    void revokeRoleFromUser_WhenValidRole_ShouldRevokeRole() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(roleRepository.findByName(RoleName.CUSTOMER)).thenReturn(Optional.of(customerRole));
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.revokeRoleFromUser("testuser", "CUSTOMER");

        // Then
        assertThat(testUser.getRoles()).doesNotContain(customerRole);
        verify(userRepository).save(testUser);
    }

    @Test
    void revokeRoleFromUser_WhenRevokingOwnSuperAdminRole_ShouldThrowAccessDeniedException() {
        // Given
        testUser.getRoles().add(superAdminRole);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(roleRepository.findByName(RoleName.SUPER_ADMIN)).thenReturn(Optional.of(superAdminRole));

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn("testuser");

        // When/Then
        assertThatThrownBy(() -> userService.revokeRoleFromUser("testuser", "SUPER_ADMIN"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Action denied: A SUPER_ADMIN cannot revoke their own SUPER_ADMIN role.");

        SecurityContextHolder.clearContext();
    }

    @Test
    void revokeRoleFromUser_WhenRoleNotAssigned_ShouldThrowIllegalStateException() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(roleRepository.findByName(RoleName.ADMIN)).thenReturn(Optional.of(adminRole));

        // When/Then
        assertThatThrownBy(() -> userService.revokeRoleFromUser("testuser", "ADMIN"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("User does not have role: ADMIN");
    }

    @Test
    void updateProfile_WhenValidInput_ShouldUpdateProfile() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        User result = userService.updateProfile("testuser", "New Full Name", "9876543210", "New Address");

        // Then
        assertThat(result.getFullName()).isEqualTo("New Full Name");
        assertThat(result.getPhone()).isEqualTo("9876543210");
        assertThat(result.getAddress()).isEqualTo("New Address");
        verify(userRepository).save(testUser);
    }

    @Test
    void updateProfilePhoto_WhenValidInput_ShouldUpdatePhotoUrl() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        User result = userService.updateProfilePhoto("testuser", "http://example.com/photo.jpg");

        // Then
        assertThat(result.getProfilePhotoUrl()).isEqualTo("http://example.com/photo.jpg");
        verify(userRepository).save(testUser);
    }
}
