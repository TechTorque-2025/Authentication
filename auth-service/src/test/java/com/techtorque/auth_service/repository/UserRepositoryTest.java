package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.Role;
import com.techtorque.auth_service.entity.RoleName;
import com.techtorque.auth_service.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Comprehensive test class for UserRepository
 * Tests all repository methods, edge cases, and database constraints
 */
@DataJpaTest
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    private User testUser;
    private Role testRole;

    @BeforeEach
    void setUp() {
        // Create test role
        testRole = Role.builder()
                .name(RoleName.CUSTOMER)
                .description("Test customer role")
                .build();
        testRole = entityManager.persistAndFlush(testRole);

        // Create test user
        testUser = User.builder()
                .username("testuser")
                .password("encodedPassword")
                .email("test@example.com")
                .fullName("Test User")
                .phone("1234567890")
                .address("123 Test Street")
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();
        testUser.addRole(testRole);
    }

    @Test
    void findByUsername_WhenUserExists_ShouldReturnUser() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        Optional<User> result = userRepository.findByUsername("testuser");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getUsername()).isEqualTo("testuser");
        assertThat(result.get().getEmail()).isEqualTo("test@example.com");
        assertThat(result.get().getFullName()).isEqualTo("Test User");
    }

    @Test
    void findByUsername_WhenUserDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<User> result = userRepository.findByUsername("nonexistent");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findByUsername_CaseSensitive_ShouldReturnEmpty() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        Optional<User> result = userRepository.findByUsername("TESTUSER");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findByEmail_WhenEmailExists_ShouldReturnUser() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        Optional<User> result = userRepository.findByEmail("test@example.com");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo("test@example.com");
        assertThat(result.get().getUsername()).isEqualTo("testuser");
    }

    @Test
    void findByEmail_WhenEmailDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<User> result = userRepository.findByEmail("nonexistent@example.com");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findByEmail_CaseSensitive_ShouldReturnEmpty() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        Optional<User> result = userRepository.findByEmail("TEST@EXAMPLE.COM");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void existsByUsername_WhenUsernameExists_ShouldReturnTrue() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        boolean exists = userRepository.existsByUsername("testuser");

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void existsByUsername_WhenUsernameDoesNotExist_ShouldReturnFalse() {
        // When
        boolean exists = userRepository.existsByUsername("nonexistent");

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    void existsByEmail_WhenEmailExists_ShouldReturnTrue() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        boolean exists = userRepository.existsByEmail("test@example.com");

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void existsByEmail_WhenEmailDoesNotExist_ShouldReturnFalse() {
        // When
        boolean exists = userRepository.existsByEmail("nonexistent@example.com");

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    void findByUsernameWithRoles_WhenUserExists_ShouldReturnUserWithRoles() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        Optional<User> result = userRepository.findByUsernameWithRoles("testuser");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getUsername()).isEqualTo("testuser");
        assertThat(result.get().getRoles()).isNotEmpty();
        assertThat(result.get().getRoles()).hasSize(1);
        assertThat(result.get().getRoles().iterator().next().getName()).isEqualTo(RoleName.CUSTOMER);
    }

    @Test
    void findByUsernameWithRoles_WhenUserDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<User> result = userRepository.findByUsernameWithRoles("nonexistent");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void save_WhenValidUser_ShouldPersistSuccessfully() {
        // Given
        User newUser = User.builder()
                .username("newuser")
                .password("password")
                .email("newuser@example.com")
                .fullName("New User")
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();

        // When
        User savedUser = userRepository.save(newUser);

        // Then
        assertThat(savedUser.getId()).isNotNull();
        assertThat(savedUser.getUsername()).isEqualTo("newuser");
        assertThat(savedUser.getEmail()).isEqualTo("newuser@example.com");
        assertThat(savedUser.getEnabled()).isTrue();
        assertThat(savedUser.getEmailVerified()).isFalse();
    }

    @Test
    void save_WithProfilePhoto_ShouldPersistPhotoData() {
        // Given
        byte[] photoData = "fake-image-data".getBytes();
        User userWithPhoto = User.builder()
                .username("photouser")
                .password("password")
                .email("photo@example.com")
                .profilePhoto(photoData)
                .profilePhotoMimeType("image/jpeg")
                .profilePhotoUpdatedAt(LocalDateTime.now())
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();

        // When
        User savedUser = userRepository.save(userWithPhoto);

        // Then
        assertThat(savedUser.getId()).isNotNull();
        assertThat(savedUser.getProfilePhoto()).isEqualTo(photoData);
        assertThat(savedUser.getProfilePhotoMimeType()).isEqualTo("image/jpeg");
        assertThat(savedUser.getProfilePhotoUpdatedAt()).isNotNull();
    }

    @Test
    void findById_WhenUserExists_ShouldReturnUser() {
        // Given
        User savedUser = entityManager.persistAndFlush(testUser);

        // When
        Optional<User> result = userRepository.findById(savedUser.getId());

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(savedUser.getId());
        assertThat(result.get().getUsername()).isEqualTo("testuser");
    }

    @Test
    void findById_WhenUserDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<User> result = userRepository.findById(999L);

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void deleteById_WhenUserExists_ShouldRemoveUser() {
        // Given
        User savedUser = entityManager.persistAndFlush(testUser);
        Long userId = savedUser.getId();

        // When
        userRepository.deleteById(userId);
        entityManager.flush();

        // Then
        Optional<User> result = userRepository.findById(userId);
        assertThat(result).isEmpty();
    }

    @Test
    void findAll_ShouldReturnAllUsers() {
        // Given
        User user1 = User.builder()
                .username("user1")
                .password("password1")
                .email("user1@example.com")
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();

        User user2 = User.builder()
                .username("user2")
                .password("password2")
                .email("user2@example.com")
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();

        entityManager.persistAndFlush(user1);
        entityManager.persistAndFlush(user2);

        // When
        var allUsers = userRepository.findAll();

        // Then
        assertThat(allUsers).hasSize(2);
        assertThat(allUsers).extracting("username")
                .containsExactlyInAnyOrder("user1", "user2");
    }

    @Test
    void count_ShouldReturnCorrectCount() {
        // Given
        entityManager.persistAndFlush(testUser);

        User secondUser = User.builder()
                .username("user2")
                .password("password2")
                .email("user2@example.com")
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();
        entityManager.persistAndFlush(secondUser);

        // When
        long count = userRepository.count();

        // Then
        assertThat(count).isEqualTo(2);
    }

    @Test
    void update_WhenUserExists_ShouldUpdateSuccessfully() {
        // Given
        User savedUser = entityManager.persistAndFlush(testUser);
        entityManager.detach(savedUser);

        // When
        savedUser.setFullName("Updated Name");
        savedUser.setPhone("9876543210");
        savedUser.setEmailVerified(true);
        User updatedUser = userRepository.save(savedUser);

        // Then
        assertThat(updatedUser.getFullName()).isEqualTo("Updated Name");
        assertThat(updatedUser.getPhone()).isEqualTo("9876543210");
        assertThat(updatedUser.getEmailVerified()).isTrue();
        assertThat(updatedUser.getUsername()).isEqualTo("testuser"); // Should remain unchanged
    }

    @Test
    void existsById_WhenUserExists_ShouldReturnTrue() {
        // Given
        User savedUser = entityManager.persistAndFlush(testUser);

        // When
        boolean exists = userRepository.existsById(savedUser.getId());

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void existsById_WhenUserDoesNotExist_ShouldReturnFalse() {
        // When
        boolean exists = userRepository.existsById(999L);

        // Then
        assertThat(exists).isFalse();
    }
}