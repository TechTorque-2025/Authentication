package com.techtorque.auth_service.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * Role entity representing user roles in the system
 * Each role contains multiple permissions that define what actions can be performed
 */
@Entity
@Table(name = "roles")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Role name from the RoleName enum (ADMIN, EMPLOYEE, CUSTOMER)
    @Column(unique = true, nullable = false)
    @Enumerated(EnumType.STRING)
    private RoleName name;
    
    // Human-readable description of the role
    private String description;
    
    // Many-to-Many relationship with User - a role can be assigned to multiple users
    @ManyToMany(mappedBy = "roles")
    private Set<User> users;
    
    // Many-to-Many relationship with Permission - a role contains multiple permissions
    // EAGER fetch ensures permissions are loaded when we load a role
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "role_permissions", // Junction table name
        joinColumns = @JoinColumn(name = "role_id"), // Foreign key to role
        inverseJoinColumns = @JoinColumn(name = "permission_id") // Foreign key to permission
    )
    private Set<Permission> permissions;
}