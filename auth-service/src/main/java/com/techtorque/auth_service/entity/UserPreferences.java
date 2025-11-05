package com.techtorque.auth_service.entity;

import jakarta.persistence.*;
import lombok.*;

/**
 * Entity representing user preferences and settings
 */
@Entity
@Table(name = "user_preferences")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserPreferences {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;
    
    @Column(nullable = false)
    @Builder.Default
    private Boolean emailNotifications = true;
    
    @Column(nullable = false)
    @Builder.Default
    private Boolean smsNotifications = false;
    
    @Column(nullable = false)
    @Builder.Default
    private Boolean pushNotifications = true;
    
    @Column(nullable = false, length = 10)
    @Builder.Default
    private String language = "en";
    
    @Column
    @Builder.Default
    private Boolean appointmentReminders = true;
    
    @Column
    @Builder.Default
    private Boolean serviceUpdates = true;
    
    @Column
    @Builder.Default
    private Boolean marketingEmails = false;
}
