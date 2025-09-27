package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;

/**
 * Repository interface for Permission entity
 * Provides database operations for permission management
 */
@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {
    
    /**
     * Find a permission by its name
     * @param name The permission name to search for (e.g., "CREATE_EMPLOYEE")
     * @return Optional containing the permission if found
     */
    Optional<Permission> findByName(String name);
    
    /**
     * Find multiple permissions by their names
     * Useful when assigning multiple permissions to a role
     * @param names Set of permission names to search for
     * @return Set of permissions found
     */
    Set<Permission> findByNameIn(Set<String> names);
    
    /**
     * Check if a permission exists by name
     * Useful for validation before creating new permissions
     * @param name The permission name to check
     * @return true if permission exists, false otherwise
     */
    boolean existsByName(String name);
}