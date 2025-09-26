package com.techtorque.auth_service.config;

import com.techtorque.auth_service.entity.Role;
import com.techtorque.auth_service.entity.RoleName;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.repository.RoleRepository;
import com.techtorque.auth_service.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

/**
 * Data seeder to initialize roles and default users with proper security
 * Runs at application startup to ensure required data exists
 */
@Component
public class DataSeeder implements CommandLineRunner {
    
    private static final Logger logger = LoggerFactory.getLogger(DataSeeder.class);
    
    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Override
    public void run(String... args) throws Exception {
        logger.info("Starting data seeding...");
        
        // First, create roles if they don't exist
        seedRoles();
        
        // Then, seed users with proper roles
        seedUsers();
        
        logger.info("Data seeding completed successfully!");
    }
    
    /**
     * Create all required roles in the system
     */
    private void seedRoles() {
        createRoleIfNotExists(RoleName.ADMIN);
        createRoleIfNotExists(RoleName.EMPLOYEE);
        createRoleIfNotExists(RoleName.CUSTOMER);
    }
    
    /**
     * Create role if it doesn't exist
     * @param roleName Role name to create
     */
    private void createRoleIfNotExists(RoleName roleName) {
        if (!roleRepository.existsByName(roleName)) {
            Role role = new Role(); // Use default constructor
            role.setName(roleName); // Set the role name
            roleRepository.save(role);
            logger.info("Created role: {}", roleName);
        }
    }
    
    /**
     * Create default users with proper password encoding and role assignments
     */
    private void seedUsers() {
        // Check if users already exist to avoid duplicates
        if (userRepository.count() > 0) {
            logger.info("Users already exist in database. Skipping user seeding.");
            return;
        }
        
        // Create default test users with roles
        createUserWithRole("admin", "admin123", "admin@techtorque.com", RoleName.ADMIN);
        createUserWithRole("employee", "emp123", "employee@techtorque.com", RoleName.EMPLOYEE);
        createUserWithRole("customer", "cust123", "customer@techtorque.com", RoleName.CUSTOMER);
        
        // Keep your original test users as customers
        createUserWithRole("user", "password", "user@techtorque.com", RoleName.CUSTOMER);
        createUserWithRole("testuser", "test123", "test@techtorque.com", RoleName.CUSTOMER);
        createUserWithRole("demo", "demo123", "demo@techtorque.com", RoleName.CUSTOMER);
    }
    
    /**
     * Create user with encoded password and assigned role
     * @param username Username for the user
     * @param password Plain text password (will be encoded)
     * @param email User's email
     * @param roleName Role to assign to the user
     */
    private void createUserWithRole(String username, String password, String email, RoleName roleName) {
        if (!userRepository.existsByUsername(username)) {
            // Create user with encoded password
            User user = new User(username, passwordEncoder.encode(password), email);
            
            // Assign role
            Set<Role> roles = new HashSet<>();
            Role role = roleRepository.findByName(roleName)
                    .orElseThrow(() -> new RuntimeException("Role " + roleName + " not found"));
            roles.add(role);
            user.setRoles(roles);
            
            // Save user
            userRepository.save(user);
            logger.info("Created user: {} with email: {} and role: {}", username, email, roleName);
        } else {
            logger.info("User {} already exists, skipping...", username);
        }
    }
}