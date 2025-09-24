package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.Role;
import com.techtorque.auth_service.entity.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for Role entity operations
 * Provides database access methods for role-related queries
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    
    /**
     * Find role by role name
     * @param name the role name to search for
     * @return Optional containing role if found
     */
    Optional<Role> findByName(RoleName name);
    
    /**
     * Check if role exists by name
     * @param name the role name to check
     * @return true if role exists, false otherwise
     */
    boolean existsByName(RoleName name);
}