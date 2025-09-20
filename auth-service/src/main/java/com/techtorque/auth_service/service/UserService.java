package com.techtorque.auth_service.service;

import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    public boolean authenticate(String username, String password) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            // For now, we'll do plain text password comparison
            // In production, you should use BCrypt or similar
            return user.getPassword().equals(password) && user.getEnabled();
        }
        return false;
    }
    
    public boolean userExists(String username) {
        return userRepository.existsByUsername(username);
    }
    
    public User createUser(String username, String password, String email) {
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Username already exists");
        }
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email already exists");
        }
        
        User user = new User(username, password, email);
        return userRepository.save(user);
    }
    
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}