package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.Role;
import com.techtorque.auth_service.entity.RoleName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Comprehensive test class for RoleRepository
 * Tests all repository methods, edge cases, and database constraints
 */
@DataJpaTest
@ActiveProfiles("test")
class RoleRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private RoleRepository roleRepository;

    private Role testRole;

    @BeforeEach
    void setUp() {
        testRole = Role.builder()
                .name(RoleName.ADMIN)
                .description("Administrator role with full access")
                .build();
    }

    @Test
    void findByName_WhenRoleExists_ShouldReturnRole() {
        // Given
        entityManager.persistAndFlush(testRole);

        // When
        Optional<Role> result = roleRepository.findByName(RoleName.ADMIN);

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getName()).isEqualTo(RoleName.ADMIN);
        assertThat(result.get().getDescription()).isEqualTo("Administrator role with full access");
    }

    @Test
    void findByName_WhenRoleDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<Role> result = roleRepository.findByName(RoleName.SUPER_ADMIN);

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void existsByName_WhenRoleExists_ShouldReturnTrue() {
        // Given
        entityManager.persistAndFlush(testRole);

        // When
        boolean exists = roleRepository.existsByName(RoleName.ADMIN);

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void existsByName_WhenRoleDoesNotExist_ShouldReturnFalse() {
        // When
        boolean exists = roleRepository.existsByName(RoleName.CUSTOMER);

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    void save_WhenValidRole_ShouldPersistSuccessfully() {
        // Given
        Role newRole = Role.builder()
                .name(RoleName.EMPLOYEE)
                .description("Employee role with limited access")
                .build();

        // When
        Role savedRole = roleRepository.save(newRole);

        // Then
        assertThat(savedRole.getId()).isNotNull();
        assertThat(savedRole.getName()).isEqualTo(RoleName.EMPLOYEE);
        assertThat(savedRole.getDescription()).isEqualTo("Employee role with limited access");
    }

    @Test
    void save_AllRoleNames_ShouldPersistAllEnumValues() {
        // Given & When & Then
        for (RoleName roleName : RoleName.values()) {
            Role role = Role.builder()
                    .name(roleName)
                    .description(roleName.name() + " role")
                    .build();

            Role savedRole = roleRepository.save(role);

            assertThat(savedRole.getId()).isNotNull();
            assertThat(savedRole.getName()).isEqualTo(roleName);
            assertThat(savedRole.getDescription()).isEqualTo(roleName.name() + " role");
        }
    }

    @Test
    void findById_WhenRoleExists_ShouldReturnRole() {
        // Given
        Role savedRole = entityManager.persistAndFlush(testRole);

        // When
        Optional<Role> result = roleRepository.findById(savedRole.getId());

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(savedRole.getId());
        assertThat(result.get().getName()).isEqualTo(RoleName.ADMIN);
    }

    @Test
    void findById_WhenRoleDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<Role> result = roleRepository.findById(999L);

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void deleteById_WhenRoleExists_ShouldRemoveRole() {
        // Given
        Role savedRole = entityManager.persistAndFlush(testRole);
        Long roleId = savedRole.getId();

        // When
        roleRepository.deleteById(roleId);
        entityManager.flush();

        // Then
        Optional<Role> result = roleRepository.findById(roleId);
        assertThat(result).isEmpty();
    }

    @Test
    void findAll_ShouldReturnAllRoles() {
        // Given
        Role adminRole = Role.builder()
                .name(RoleName.ADMIN)
                .description("Admin role")
                .build();

        Role customerRole = Role.builder()
                .name(RoleName.CUSTOMER)
                .description("Customer role")
                .build();

        entityManager.persistAndFlush(adminRole);
        entityManager.persistAndFlush(customerRole);

        // When
        var allRoles = roleRepository.findAll();

        // Then
        assertThat(allRoles).hasSize(2);
        assertThat(allRoles).extracting("name")
                .containsExactlyInAnyOrder(RoleName.ADMIN, RoleName.CUSTOMER);
    }

    @Test
    void count_ShouldReturnCorrectCount() {
        // Given
        entityManager.persistAndFlush(testRole);

        Role secondRole = Role.builder()
                .name(RoleName.EMPLOYEE)
                .description("Employee role")
                .build();
        entityManager.persistAndFlush(secondRole);

        // When
        long count = roleRepository.count();

        // Then
        assertThat(count).isEqualTo(2);
    }

    @Test
    void update_WhenRoleExists_ShouldUpdateSuccessfully() {
        // Given
        Role savedRole = entityManager.persistAndFlush(testRole);
        entityManager.detach(savedRole);

        // When
        savedRole.setDescription("Updated admin role description");
        Role updatedRole = roleRepository.save(savedRole);

        // Then
        assertThat(updatedRole.getDescription()).isEqualTo("Updated admin role description");
        assertThat(updatedRole.getName()).isEqualTo(RoleName.ADMIN); // Should remain unchanged
    }

    @Test
    void existsById_WhenRoleExists_ShouldReturnTrue() {
        // Given
        Role savedRole = entityManager.persistAndFlush(testRole);

        // When
        boolean exists = roleRepository.existsById(savedRole.getId());

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void existsById_WhenRoleDoesNotExist_ShouldReturnFalse() {
        // When
        boolean exists = roleRepository.existsById(999L);

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    void save_WithNullDescription_ShouldPersistSuccessfully() {
        // Given
        Role roleWithoutDescription = Role.builder()
                .name(RoleName.CUSTOMER)
                .description(null)
                .build();

        // When
        Role savedRole = roleRepository.save(roleWithoutDescription);

        // Then
        assertThat(savedRole.getId()).isNotNull();
        assertThat(savedRole.getName()).isEqualTo(RoleName.CUSTOMER);
        assertThat(savedRole.getDescription()).isNull();
    }

    @Test
    void save_WithEmptyDescription_ShouldPersistSuccessfully() {
        // Given
        Role roleWithEmptyDescription = Role.builder()
                .name(RoleName.CUSTOMER)
                .description("")
                .build();

        // When
        Role savedRole = roleRepository.save(roleWithEmptyDescription);

        // Then
        assertThat(savedRole.getId()).isNotNull();
        assertThat(savedRole.getName()).isEqualTo(RoleName.CUSTOMER);
        assertThat(savedRole.getDescription()).isEmpty();
    }
}