package com.techtorque.auth_service.config;

import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataSeeder implements CommandLineRunner {
    
    private static final Logger logger = LoggerFactory.getLogger(DataSeeder.class);
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public void run(String... args) throws Exception {
        seedUsers();
    }
    
    private void seedUsers() {
        logger.info("Starting data seeding...");
        
        // Check if users already exist to avoid duplicates
        if (userRepository.count() > 0) {
            logger.info("Users already exist in database. Skipping seeding.");
            return;
        }
        
        // Create default test users
        createUserIfNotExists("user", "password", "user@techtorque.com");
        createUserIfNotExists("admin", "admin123", "admin@techtorque.com");
        createUserIfNotExists("testuser", "test123", "test@techtorque.com");
        createUserIfNotExists("demo", "demo123", "demo@techtorque.com");
        
        logger.info("Data seeding completed successfully!");
    }
    
    private void createUserIfNotExists(String username, String password, String email) {
        if (!userRepository.existsByUsername(username)) {
            User user = new User(username, password, email);
            userRepository.save(user);
            logger.info("Created user: {} with email: {}", username, email);
        } else {
            logger.info("User {} already exists, skipping...", username);
        }
    }
}