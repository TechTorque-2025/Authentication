package com.techtorque.auth_service.service;

import com.techtorque.auth_service.entity.Role;
import com.techtorque.auth_service.entity.RoleName;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.repository.RoleRepository;
import com.techtorque.auth_service.repository.LoginLockRepository;
import com.techtorque.auth_service.repository.UserRepository;
import com.techtorque.auth_service.repository.RefreshTokenRepository;
import com.techtorque.auth_service.repository.VerificationTokenRepository;
import com.techtorque.auth_service.repository.LoginLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.AccessDeniedException;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Service class for user management with restricted registration
 * - Only customers can register publicly
 * - Only admins can create employees and other admins
 * - Implements Spring Security's UserDetailsService for authentication
 */
@Service
@Transactional
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginLockRepository loginLockRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final LoginLogRepository loginLogRepository;
    private final EmailService emailService;
    private final TokenService tokenService;

    public UserService(UserRepository userRepository, RoleRepository roleRepository,
            @Lazy PasswordEncoder passwordEncoder,
            LoginLockRepository loginLockRepository, RefreshTokenRepository refreshTokenRepository,
            VerificationTokenRepository verificationTokenRepository, LoginLogRepository loginLogRepository,
            EmailService emailService, TokenService tokenService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.loginLockRepository = loginLockRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.verificationTokenRepository = verificationTokenRepository;
        this.loginLogRepository = loginLogRepository;
        this.emailService = emailService;
        this.tokenService = tokenService;
    }

    /**
     * Load user by username for Spring Security authentication
     * This method is called during login to authenticate the user
     * 
     * @param username The username to authenticate
     * @return UserDetails object with user info and authorities
     * @throws UsernameNotFoundException if user not found
     */
    @Override
    public UserDetails loadUserByUsername(String identifier) throws UsernameNotFoundException {
        // Support login by either username or email.
        // Try to find by username first, then fall back to email.
        java.util.Optional<User> userOpt = userRepository.findByUsername(identifier);
        if (userOpt.isEmpty()) {
            userOpt = userRepository.findByEmail(identifier);
        }

        User user = userOpt.orElseThrow(() -> new UsernameNotFoundException("User not found: " + identifier));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(getAuthorities(user)) // Convert roles/permissions to Spring Security authorities
                .accountExpired(false)
                .accountLocked(!user.getEnabled()) // Account locked if user is disabled
                .credentialsExpired(false)
                .disabled(!user.getEnabled())
                .build();
    }

    /**
     * Convert user roles and permissions to Spring Security GrantedAuthority
     * objects
     * This enables role-based and permission-based security checks
     * 
     * @param user The user whose authorities to build
     * @return Collection of granted authorities
     */
    private Collection<? extends GrantedAuthority> getAuthorities(User user) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        // Add role-based authorities (prefixed with ROLE_)
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName().name()));

            // Add permission-based authorities (used for @PreAuthorize checks)
            role.getPermissions()
                    .forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission.getName())));
        });

        return authorities;
    }

    /**
     * Register a new customer (public registration)
     * Only allows CUSTOMER role creation through public endpoint
     * 
     * @param username Unique username
     * @param email    Unique email
     * @param password Plain text password (will be encoded)
     * @return The created customer user
     * @throws RuntimeException if username or email already exists
     */
    public User registerCustomer(String username, String email, String password) {
        // Validate username doesn't exist
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }

        // Validate email doesn't exist
        if (userRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("Email already exists: " + email);
        }

        // Get CUSTOMER role from database
        Role customerRole = roleRepository.findByName(RoleName.CUSTOMER)
                .orElseThrow(() -> new EntityNotFoundException("Customer role not found"));

        // Create user with CUSTOMER role only
        User user = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .enabled(true)
                .roles(Set.of(customerRole)) // Only CUSTOMER role
                .build();

        return userRepository.save(user);
    }

    /**
     * Create an employee account (admin only)
     * Only admins can call this method
     * 
     * @param username Unique username
     * @param email    Unique email
     * @param password Plain text password (will be encoded)
     * @param fullName Full name of the employee
     * @return The created employee user
     * @throws RuntimeException if username or email already exists
     */
    public User createEmployee(String username, String email, String password, String fullName) {
        // Validate username doesn't exist
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }

        // Validate email doesn't exist
        if (userRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("Email already exists: " + email);
        }

        // Get EMPLOYEE role from database
        Role employeeRole = roleRepository.findByName(RoleName.EMPLOYEE)
                .orElseThrow(() -> new EntityNotFoundException("Employee role not found"));

        // Create user with EMPLOYEE role
        User user = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .fullName(fullName)
                .enabled(true)
                .roles(Set.of(employeeRole)) // Only EMPLOYEE role
                .build();

        User savedUser = userRepository.save(user);

        // Create verification token and send email
        String token = tokenService.createVerificationToken(savedUser);
        emailService.sendVerificationEmail(savedUser.getEmail(), savedUser.getFullName(), token);

        return savedUser;
    }

    /**
     * Create an admin account (admin only)
     * Only existing admins can call this method
     * 
     * @param username Unique username
     * @param email    Unique email
     * @param password Plain text password (will be encoded)
     * @param fullName Full name of the admin
     * @return The created admin user
     * @throws RuntimeException if username or email already exists
     */
    public User createAdmin(String username, String email, String password, String fullName) {
        // Validate username doesn't exist
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }

        // Validate email doesn't exist
        if (userRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("Email already exists: " + email);
        }

        // Get ADMIN role from database
        Role adminRole = roleRepository.findByName(RoleName.ADMIN)
                .orElseThrow(() -> new EntityNotFoundException("Admin role not found"));

        // Create user with ADMIN role
        User user = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .fullName(fullName)
                .enabled(true)
                .roles(Set.of(adminRole)) // Only ADMIN role
                .build();

        User savedUser = userRepository.save(user);

        // Create verification token and send email
        String token = tokenService.createVerificationToken(savedUser);
        emailService.sendVerificationEmail(savedUser.getEmail(), savedUser.getFullName(), token);

        return savedUser;
    }

    /**
     * Find user by username
     * 
     * @param username Username to search for
     * @return Optional containing user if found
     */
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Find user by email
     * 
     * @param email Email to search for
     * @return Optional containing user if found
     */
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    /**
     * Get all users in the system (admin only)
     * 
     * @return List of all users
     */
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    /**
     * Get all permissions for a user (from all their roles)
     * 
     * @param username Username to get permissions for
     * @return Set of permission names
     */
    public Set<String> getUserPermissions(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        return user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(permission -> permission.getName())
                .collect(Collectors.toSet());
    }

    /**
     * Get all roles for a user
     * 
     * @param username Username to get roles for
     * @return Set of role names
     */
    public Set<String> getUserRoles(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        return user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet());
    }

    /**
     * Enable a user account (admin only)
     * 
     * @param username Username to enable
     */
    public void enableUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));
        user.setEnabled(true);
        userRepository.save(user);
    }

    /**
     * Disable a user account (admin only)
     * 
     * @param username Username to disable
     */
    public void disableUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));
        user.setEnabled(false);
        userRepository.save(user);
    }

    /**
     * Delete a user from the system (admin only)
     * 
     * @param username Username to delete
     * @throws RuntimeException if user not found
     */
    public void deleteUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        // Clear all related records before deleting the user to avoid foreign key
        // constraint issues

        // Clear roles
        user.getRoles().clear();
        userRepository.save(user);

        // Delete related refresh tokens
        refreshTokenRepository.deleteByUser(user);

        // Delete related verification tokens
        verificationTokenRepository.deleteByUser(user);

        // Delete related login locks
        loginLockRepository.deleteByUsername(username);

        // Delete related login logs
        loginLogRepository.deleteByUsername(username);

        // Finally, delete the user
        userRepository.delete(user);
    }

    /**
     * Clear login lock for a username (admin action).
     * Resets failed attempts and lock timestamp if an entry exists.
     */
    public void clearLoginLock(String username) {
        java.util.Optional<com.techtorque.auth_service.entity.LoginLock> lockOpt = loginLockRepository
                .findByUsername(username);
        if (lockOpt.isPresent()) {
            com.techtorque.auth_service.entity.LoginLock lock = lockOpt.get();
            lock.setFailedAttempts(0);
            lock.setLockUntil(null);
            loginLockRepository.save(lock);
        }
    }

    /**
     * Check if a user has a specific role
     * 
     * @param username Username to check
     * @param roleName Role to check for
     * @return true if user has the role
     */
    public boolean hasRole(String username, RoleName roleName) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        return user.getRoles().stream()
                .anyMatch(role -> role.getName().equals(roleName));
    }

    /**
     * Check if a user has a specific permission
     * 
     * @param username       Username to check
     * @param permissionName Permission to check for
     * @return true if user has the permission through any of their roles
     */
    public boolean hasPermission(String username, String permissionName) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        return user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .anyMatch(permission -> permission.getName().equals(permissionName));
    }

    /**
     * Update user details (admin only)
     * 
     * @param username    Username of the user to update
     * @param newUsername New username (optional)
     * @param newEmail    New email (optional)
     * @param enabled     New enabled status (optional)
     * @return Updated user
     * @throws RuntimeException if user not found or new values already exist
     */
    public User updateUserDetails(String username, String newUsername, String newEmail, Boolean enabled) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        // Check if new username is provided and different
        if (newUsername != null && !newUsername.equals(user.getUsername())) {
            if (userRepository.existsByUsername(newUsername)) {
                throw new IllegalArgumentException("Username already exists: " + newUsername);
            }
            user.setUsername(newUsername);
        }

        // Check if new email is provided and different
        if (newEmail != null && !newEmail.equals(user.getEmail())) {
            if (userRepository.existsByEmail(newEmail)) {
                throw new IllegalArgumentException("Email already exists: " + newEmail);
            }
            user.setEmail(newEmail);
        }

        // Update enabled status if provided
        if (enabled != null) {
            user.setEnabled(enabled);
        }

        return userRepository.save(user);
    }

    /**
     * Reset a user's password (admin only)
     * 
     * @param username    Username whose password to reset
     * @param newPassword New password (plain text)
     * @throws RuntimeException if user not found
     */
    public void resetUserPassword(String username, String newPassword) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    /**
     * Change user's own password (requires current password verification)
     * 
     * @param username        Username of the user changing password
     * @param currentPassword Current password for verification
     * @param newPassword     New password (plain text)
     * @throws RuntimeException if user not found or current password is incorrect
     */
    public void changeUserPassword(String username, String currentPassword, String newPassword) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        // Verify current password
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new IllegalStateException("Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    /**
     * Assign a role to a user (admin only)
     * 
     * @param username Username to assign role to
     * @param roleName Role name to assign
     * @throws RuntimeException if user or role not found, or role already assigned
     */
    public void assignRoleToUser(String username, String roleName) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        RoleName roleNameEnum;
        try {
            roleNameEnum = RoleName.valueOf(roleName.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid role name: " + roleName);
        }

        // Rule: Only a SUPER_ADMIN can assign the ADMIN role.
        if (roleNameEnum == RoleName.ADMIN) {
            Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
            if (currentUser == null) {
                throw new AccessDeniedException("Permission denied: unauthenticated users cannot assign roles.");
            }
            boolean isSuperAdmin = currentUser.getAuthorities().stream()
                    .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_SUPER_ADMIN"));

            if (!isSuperAdmin) {
                throw new AccessDeniedException("Permission denied: Only a SUPER_ADMIN can assign the ADMIN role.");
            }
        }

        Role role = roleRepository.findByName(roleNameEnum)
                .orElseThrow(() -> new EntityNotFoundException("Role not found: " + roleName));

        if (user.getRoles().contains(role)) {
            throw new IllegalStateException("User already has role: " + roleName);
        }

        user.getRoles().add(role);
        userRepository.save(user);
    }

    /**
     * Revoke a role from a user (admin only)
     * 
     * @param username Username to revoke role from
     * @param roleName Role name to revoke
     * @throws RuntimeException if user or role not found, or role not assigned
     */
    public void revokeRoleFromUser(String username, String roleName) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        RoleName roleNameEnum;
        try {
            roleNameEnum = RoleName.valueOf(roleName.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid role name: " + roleName);
        }

        // Rule: A user cannot revoke their own SUPER_ADMIN role.
        if (roleNameEnum == RoleName.SUPER_ADMIN) {
            Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
            if (currentUser == null) {
                throw new AccessDeniedException("Permission denied: unauthenticated users cannot revoke roles.");
            }
            String currentUsername = currentUser.getName();

            if (currentUsername.equals(username)) {
                throw new AccessDeniedException(
                        "Action denied: A SUPER_ADMIN cannot revoke their own SUPER_ADMIN role.");
            }
        }

        Role role = roleRepository.findByName(roleNameEnum)
                .orElseThrow(() -> new EntityNotFoundException("Role not found: " + roleName));

        if (!user.getRoles().contains(role)) {
            throw new IllegalStateException("User does not have role: " + roleName);
        }

        user.getRoles().remove(role);
        userRepository.save(user);
    }

    /**
     * Update user profile
     */
    public User updateProfile(String username, String fullName, String phone, String address) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        if (fullName != null) {
            user.setFullName(fullName);
        }
        if (phone != null) {
            user.setPhone(phone);
        }
        if (address != null) {
            user.setAddress(address);
        }

        return userRepository.save(user);
    }

    /**
     * Update profile photo URL
     */
    public User updateProfilePhoto(String username, String photoUrl) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));

        user.setProfilePhotoUrl(photoUrl);
        return userRepository.save(user);
    }
}
