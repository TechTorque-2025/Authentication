package com.techtorque.auth_service.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * Permission entity to represent individual permissions in the system
 * Each permission represents a specific action that can be performed
 */
@Entity
@Table(name = "permissions")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Permission {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Unique permission name (e.g., CREATE_USER, VIEW_REPORTS)
    @Column(unique = true, nullable = false)
    private String name;
    
    // Human-readable description of what this permission allows
    private String description;
    
    // Many-to-Many relationship with Role - a permission can be assigned to multiple roles
    @ManyToMany(mappedBy = "permissions")
    private Set<Role> roles;
}