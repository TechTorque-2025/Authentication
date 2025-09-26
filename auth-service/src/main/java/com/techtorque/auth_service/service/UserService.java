package com.techtorque.auth_service.service;

import com.techtorque.auth_service.entity.Role;
import com.techtorque.auth_service.entity.RoleName;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.repository.RoleRepository;
import com.techtorque.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
@RequiredArgsConstructor
@Transactional
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Load user by username for Spring Security authentication
     * This method is called during login to authenticate the user
     * @param username The username to authenticate
     * @return UserDetails object with user info and authorities
     * @throws UsernameNotFoundException if user not found
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

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
     * Convert user roles and permissions to Spring Security GrantedAuthority objects
     * This enables role-based and permission-based security checks
     * @param user The user whose authorities to build
     * @return Collection of granted authorities
     */
    private Collection<? extends GrantedAuthority> getAuthorities(User user) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        // Add role-based authorities (prefixed with ROLE_)
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName().name()));
            
            // Add permission-based authorities (used for @PreAuthorize checks)
            role.getPermissions().forEach(permission -> 
                authorities.add(new SimpleGrantedAuthority(permission.getName()))
            );
        });
        
        return authorities;
    }

    /**
     * Register a new customer (public registration)
     * Only allows CUSTOMER role creation through public endpoint
     * @param username Unique username
     * @param email Unique email
     * @param password Plain text password (will be encoded)
     * @return The created customer user
     * @throws RuntimeException if username or email already exists
     */
    public User registerCustomer(String username, String email, String password) {
        // Validate username doesn't exist
        if (userRepository.findByUsername(username).isPresent()) {
            throw new RuntimeException("Username already exists: " + username);
        }
        
        // Validate email doesn't exist
        if (userRepository.findByEmail(email).isPresent()) {
            throw new RuntimeException("Email already exists: " + email);
        }

        // Get CUSTOMER role from database
        Role customerRole = roleRepository.findByName(RoleName.CUSTOMER)
                .orElseThrow(() -> new RuntimeException("Customer role not found"));

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
     * @param username Unique username
     * @param email Unique email
     * @param password Plain text password (will be encoded)
     * @return The created employee user
     * @throws RuntimeException if username or email already exists
     */
    public User createEmployee(String username, String email, String password) {
        // Validate username doesn't exist
        if (userRepository.findByUsername(username).isPresent()) {
            throw new RuntimeException("Username already exists: " + username);
        }
        
        // Validate email doesn't exist
        if (userRepository.findByEmail(email).isPresent()) {
            throw new RuntimeException("Email already exists: " + email);
        }

        // Get EMPLOYEE role from database
        Role employeeRole = roleRepository.findByName(RoleName.EMPLOYEE)
                .orElseThrow(() -> new RuntimeException("Employee role not found"));

        // Create user with EMPLOYEE role
        User user = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .enabled(true)
                .roles(Set.of(employeeRole)) // Only EMPLOYEE role
                .build();

        return userRepository.save(user);
    }

    /**
     * Create an admin account (admin only)
     * Only existing admins can call this method
     * @param username Unique username
     * @param email Unique email
     * @param password Plain text password (will be encoded)
     * @return The created admin user
     * @throws RuntimeException if username or email already exists
     */
    public User createAdmin(String username, String email, String password) {
        // Validate username doesn't exist
        if (userRepository.findByUsername(username).isPresent()) {
            throw new RuntimeException("Username already exists: " + username);
        }
        
        // Validate email doesn't exist
        if (userRepository.findByEmail(email).isPresent()) {
            throw new RuntimeException("Email already exists: " + email);
        }

        // Get ADMIN role from database
        Role adminRole = roleRepository.findByName(RoleName.ADMIN)
                .orElseThrow(() -> new RuntimeException("Admin role not found"));

        // Create user with ADMIN role
        User user = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .enabled(true)
                .roles(Set.of(adminRole)) // Only ADMIN role
                .build();

        return userRepository.save(user);
    }

    /**
     * Find user by username
     * @param username Username to search for
     * @return Optional containing user if found
     */
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Find user by email
     * @param email Email to search for
     * @return Optional containing user if found
     */
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    /**
     * Get all users in the system (admin only)
     * @return List of all users
     */
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    /**
     * Get all permissions for a user (from all their roles)
     * @param username Username to get permissions for
     * @return Set of permission names
     */
    public Set<String> getUserPermissions(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
        
        return user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(permission -> permission.getName())
                .collect(Collectors.toSet());
    }

    /**
     * Get all roles for a user
     * @param username Username to get roles for
     * @return Set of role names
     */
    public Set<String> getUserRoles(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
        
        return user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet());
    }

    /**
     * Enable a user account (admin only)
     * @param username Username to enable
     */
    public void enableUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
        user.setEnabled(true);
        userRepository.save(user);
    }

    /**
     * Disable a user account (admin only)
     * @param username Username to disable
     */
    public void disableUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
        user.setEnabled(false);
        userRepository.save(user);
    }

    /**
     * Delete a user from the system (admin only)
     * @param username Username to delete
     * @throws RuntimeException if user not found
     */
    public void deleteUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
        userRepository.delete(user);
    }

    /**
     * Check if a user has a specific role
     * @param username Username to check
     * @param roleName Role to check for
     * @return true if user has the role
     */
    public boolean hasRole(String username, RoleName roleName) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
        
        return user.getRoles().stream()
                .anyMatch(role -> role.getName().equals(roleName));
    }

    /**
     * Check if a user has a specific permission
     * @param username Username to check
     * @param permissionName Permission to check for
     * @return true if user has the permission through any of their roles
     */
    public boolean hasPermission(String username, String permissionName) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
        
        return user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .anyMatch(permission -> permission.getName().equals(permissionName));
    }
}