package com.techtorque.auth_service.service;

import com.techtorque.auth_service.dto.response.UserPreferencesDto;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.entity.UserPreferences;
import com.techtorque.auth_service.repository.UserPreferencesRepository;
import com.techtorque.auth_service.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service for managing user preferences
 */
@Service
@Transactional
public class PreferencesService {
    
    @Autowired
    private UserPreferencesRepository preferencesRepository;
    
    @Autowired
    private UserRepository userRepository;
    
    /**
     * Get user preferences (creates default if not exists)
     */
    public UserPreferencesDto getUserPreferences(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));
        
        UserPreferences preferences = preferencesRepository.findByUser(user)
                .orElseGet(() -> createDefaultPreferences(user));
        
        return convertToDto(preferences);
    }
    
    /**
     * Update user preferences
     */
    public UserPreferencesDto updateUserPreferences(String username, UserPreferencesDto dto) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + username));
        
        UserPreferences preferences = preferencesRepository.findByUser(user)
                .orElseGet(() -> createDefaultPreferences(user));
        
        if (dto.getEmailNotifications() != null) {
            preferences.setEmailNotifications(dto.getEmailNotifications());
        }
        if (dto.getSmsNotifications() != null) {
            preferences.setSmsNotifications(dto.getSmsNotifications());
        }
        if (dto.getPushNotifications() != null) {
            preferences.setPushNotifications(dto.getPushNotifications());
        }
        if (dto.getLanguage() != null) {
            preferences.setLanguage(dto.getLanguage());
        }
        if (dto.getAppointmentReminders() != null) {
            preferences.setAppointmentReminders(dto.getAppointmentReminders());
        }
        if (dto.getServiceUpdates() != null) {
            preferences.setServiceUpdates(dto.getServiceUpdates());
        }
        if (dto.getMarketingEmails() != null) {
            preferences.setMarketingEmails(dto.getMarketingEmails());
        }
        
        UserPreferences saved = preferencesRepository.save(preferences);
        return convertToDto(saved);
    }
    
    /**
     * Create default preferences for a user
     */
    private UserPreferences createDefaultPreferences(User user) {
        UserPreferences preferences = UserPreferences.builder()
                .user(user)
                .emailNotifications(true)
                .smsNotifications(false)
                .pushNotifications(true)
                .language("en")
                .appointmentReminders(true)
                .serviceUpdates(true)
                .marketingEmails(false)
                .build();
        
        return preferencesRepository.save(preferences);
    }
    
    /**
     * Convert entity to DTO
     */
    private UserPreferencesDto convertToDto(UserPreferences preferences) {
        return UserPreferencesDto.builder()
                .emailNotifications(preferences.getEmailNotifications())
                .smsNotifications(preferences.getSmsNotifications())
                .pushNotifications(preferences.getPushNotifications())
                .language(preferences.getLanguage())
                .appointmentReminders(preferences.getAppointmentReminders())
                .serviceUpdates(preferences.getServiceUpdates())
                .marketingEmails(preferences.getMarketingEmails())
                .build();
    }
}
