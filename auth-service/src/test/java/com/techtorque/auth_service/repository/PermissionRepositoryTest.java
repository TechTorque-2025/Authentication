package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.Permission;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Comprehensive test class for PermissionRepository
 * Tests all repository methods, edge cases, and database constraints
 */
@DataJpaTest
@ActiveProfiles("test")
class PermissionRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private PermissionRepository permissionRepository;

    private Permission testPermission;

    @BeforeEach
    void setUp() {
        testPermission = Permission.builder()
                .name("CREATE_USER")
                .description("Permission to create new users")
                .build();
    }

    @Test
    void save_WhenValidPermission_ShouldPersistSuccessfully() {
        // When
        Permission savedPermission = permissionRepository.save(testPermission);

        // Then
        assertThat(savedPermission.getId()).isNotNull();
        assertThat(savedPermission.getName()).isEqualTo("CREATE_USER");
        assertThat(savedPermission.getDescription()).isEqualTo("Permission to create new users");
    }

    @Test
    void findByName_WhenPermissionExists_ShouldReturnPermission() {
        // Given
        entityManager.persistAndFlush(testPermission);

        // When
        Optional<Permission> result = permissionRepository.findByName("CREATE_USER");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getName()).isEqualTo("CREATE_USER");
        assertThat(result.get().getDescription()).isEqualTo("Permission to create new users");
    }

    @Test
    void findByName_WhenPermissionDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<Permission> result = permissionRepository.findByName("NON_EXISTENT");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findByName_CaseSensitive_ShouldReturnEmpty() {
        // Given
        entityManager.persistAndFlush(testPermission);

        // When
        Optional<Permission> result = permissionRepository.findByName("create_user");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findByNameIn_WhenPermissionsExist_ShouldReturnMatchingPermissions() {
        // Given
        Permission permission1 = Permission.builder()
                .name("READ_USER")
                .description("Permission to read user data")
                .build();

        Permission permission2 = Permission.builder()
                .name("UPDATE_USER")
                .description("Permission to update user data")
                .build();

        Permission permission3 = Permission.builder()
                .name("DELETE_USER")
                .description("Permission to delete users")
                .build();

        entityManager.persistAndFlush(testPermission);
        entityManager.persistAndFlush(permission1);
        entityManager.persistAndFlush(permission2);
        entityManager.persistAndFlush(permission3);

        // When
        Set<String> names = Set.of("CREATE_USER", "READ_USER", "NON_EXISTENT");
        Set<Permission> result = permissionRepository.findByNameIn(names);

        // Then
        assertThat(result).hasSize(2);
        assertThat(result).extracting("name")
                .containsExactlyInAnyOrder("CREATE_USER", "READ_USER");
    }

    @Test
    void findByNameIn_WhenEmptySet_ShouldReturnEmptySet() {
        // Given
        entityManager.persistAndFlush(testPermission);

        // When
        Set<Permission> result = permissionRepository.findByNameIn(Set.of());

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findByNameIn_WhenNoMatches_ShouldReturnEmptySet() {
        // Given
        entityManager.persistAndFlush(testPermission);

        // When
        Set<String> names = Set.of("NON_EXISTENT1", "NON_EXISTENT2");
        Set<Permission> result = permissionRepository.findByNameIn(names);

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void existsByName_WhenPermissionExists_ShouldReturnTrue() {
        // Given
        entityManager.persistAndFlush(testPermission);

        // When
        boolean exists = permissionRepository.existsByName("CREATE_USER");

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void existsByName_WhenPermissionDoesNotExist_ShouldReturnFalse() {
        // When
        boolean exists = permissionRepository.existsByName("NON_EXISTENT");

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    void findById_WhenPermissionExists_ShouldReturnPermission() {
        // Given
        Permission savedPermission = entityManager.persistAndFlush(testPermission);

        // When
        Optional<Permission> result = permissionRepository.findById(savedPermission.getId());

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(savedPermission.getId());
        assertThat(result.get().getName()).isEqualTo("CREATE_USER");
    }

    @Test
    void findById_WhenPermissionDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<Permission> result = permissionRepository.findById(999L);

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findAll_ShouldReturnAllPermissions() {
        // Given
        Permission permission1 = Permission.builder()
                .name("READ_REPORTS")
                .description("Permission to read reports")
                .build();

        Permission permission2 = Permission.builder()
                .name("WRITE_REPORTS")
                .description("Permission to write reports")
                .build();

        entityManager.persistAndFlush(permission1);
        entityManager.persistAndFlush(permission2);

        // When
        List<Permission> allPermissions = permissionRepository.findAll();

        // Then
        assertThat(allPermissions).hasSize(2);
        assertThat(allPermissions).extracting("name")
                .containsExactlyInAnyOrder("READ_REPORTS", "WRITE_REPORTS");
    }

    @Test
    void count_ShouldReturnCorrectCount() {
        // Given
        entityManager.persistAndFlush(testPermission);

        Permission secondPermission = Permission.builder()
                .name("DELETE_USER")
                .description("Permission to delete users")
                .build();
        entityManager.persistAndFlush(secondPermission);

        // When
        long count = permissionRepository.count();

        // Then
        assertThat(count).isEqualTo(2);
    }

    @Test
    void update_WhenPermissionExists_ShouldUpdateSuccessfully() {
        // Given
        Permission savedPermission = entityManager.persistAndFlush(testPermission);
        entityManager.detach(savedPermission);

        // When
        savedPermission.setDescription("Updated description for creating users");
        Permission updatedPermission = permissionRepository.save(savedPermission);

        // Then
        assertThat(updatedPermission.getDescription()).isEqualTo("Updated description for creating users");
        assertThat(updatedPermission.getName()).isEqualTo("CREATE_USER"); // Should remain unchanged
    }

    @Test
    void deleteById_WhenPermissionExists_ShouldRemovePermission() {
        // Given
        Permission savedPermission = entityManager.persistAndFlush(testPermission);
        Long permissionId = savedPermission.getId();

        // When
        permissionRepository.deleteById(permissionId);
        entityManager.flush();

        // Then
        Optional<Permission> result = permissionRepository.findById(permissionId);
        assertThat(result).isEmpty();
    }

    @Test
    void save_WithNullDescription_ShouldPersistSuccessfully() {
        // Given
        Permission permissionWithoutDescription = Permission.builder()
                .name("SIMPLE_PERMISSION")
                .description(null)
                .build();

        // When
        Permission savedPermission = permissionRepository.save(permissionWithoutDescription);

        // Then
        assertThat(savedPermission.getId()).isNotNull();
        assertThat(savedPermission.getName()).isEqualTo("SIMPLE_PERMISSION");
        assertThat(savedPermission.getDescription()).isNull();
    }

    @Test
    void save_WithEmptyDescription_ShouldPersistSuccessfully() {
        // Given
        Permission permissionWithEmptyDescription = Permission.builder()
                .name("ANOTHER_PERMISSION")
                .description("")
                .build();

        // When
        Permission savedPermission = permissionRepository.save(permissionWithEmptyDescription);

        // Then
        assertThat(savedPermission.getId()).isNotNull();
        assertThat(savedPermission.getName()).isEqualTo("ANOTHER_PERMISSION");
        assertThat(savedPermission.getDescription()).isEmpty();
    }

    @Test
    void existsById_WhenPermissionExists_ShouldReturnTrue() {
        // Given
        Permission savedPermission = entityManager.persistAndFlush(testPermission);

        // When
        boolean exists = permissionRepository.existsById(savedPermission.getId());

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void existsById_WhenPermissionDoesNotExist_ShouldReturnFalse() {
        // When
        boolean exists = permissionRepository.existsById(999L);

        // Then
        assertThat(exists).isFalse();
    }
}