package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.LoginLock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Comprehensive test class for LoginLockRepository
 * Tests all repository methods, edge cases, and database constraints
 */
@DataJpaTest
@ActiveProfiles("test")
class LoginLockRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private LoginLockRepository loginLockRepository;

    private LoginLock testLoginLock;

    @BeforeEach
    void setUp() {
        testLoginLock = LoginLock.builder()
                .username("testuser")
                .failedAttempts(3)
                .lockUntil(LocalDateTime.now().plusMinutes(15))
                .build();
    }

    @Test
    void save_WhenValidLoginLock_ShouldPersistSuccessfully() {
        // When
        LoginLock savedLock = loginLockRepository.save(testLoginLock);

        // Then
        assertThat(savedLock.getId()).isNotNull();
        assertThat(savedLock.getUsername()).isEqualTo("testuser");
        assertThat(savedLock.getFailedAttempts()).isEqualTo(3);
        assertThat(savedLock.getLockUntil()).isNotNull();
    }

    @Test
    void save_WithDefaultFailedAttempts_ShouldUseZero() {
        // Given
        LoginLock lockWithDefaults = LoginLock.builder()
                .username("newuser")
                .build();

        // When
        LoginLock savedLock = loginLockRepository.save(lockWithDefaults);

        // Then
        assertThat(savedLock.getId()).isNotNull();
        assertThat(savedLock.getUsername()).isEqualTo("newuser");
        assertThat(savedLock.getFailedAttempts()).isEqualTo(0);
        assertThat(savedLock.getLockUntil()).isNull();
    }

    @Test
    void findByUsername_WhenLockExists_ShouldReturnLock() {
        // Given
        entityManager.persistAndFlush(testLoginLock);

        // When
        Optional<LoginLock> result = loginLockRepository.findByUsername("testuser");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getUsername()).isEqualTo("testuser");
        assertThat(result.get().getFailedAttempts()).isEqualTo(3);
    }

    @Test
    void findByUsername_WhenLockDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<LoginLock> result = loginLockRepository.findByUsername("nonexistent");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findByUsername_CaseSensitive_ShouldReturnEmpty() {
        // Given
        entityManager.persistAndFlush(testLoginLock);

        // When
        Optional<LoginLock> result = loginLockRepository.findByUsername("TESTUSER");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    @Transactional
    void deleteByUsername_WhenLockExists_ShouldDeleteLock() {
        // Given
        entityManager.persistAndFlush(testLoginLock);

        LoginLock anotherLock = LoginLock.builder()
                .username("anotheruser")
                .failedAttempts(1)
                .build();
        entityManager.persistAndFlush(anotherLock);

        // When
        loginLockRepository.deleteByUsername("testuser");
        entityManager.flush();

        // Then
        Optional<LoginLock> deletedLock = loginLockRepository.findByUsername("testuser");
        Optional<LoginLock> remainingLock = loginLockRepository.findByUsername("anotheruser");

        assertThat(deletedLock).isEmpty();
        assertThat(remainingLock).isPresent();
    }

    @Test
    void update_WhenLockExists_ShouldUpdateSuccessfully() {
        // Given
        LoginLock savedLock = entityManager.persistAndFlush(testLoginLock);
        entityManager.detach(savedLock);

        // When
        savedLock.setFailedAttempts(5);
        savedLock.setLockUntil(LocalDateTime.now().plusMinutes(30));
        LoginLock updatedLock = loginLockRepository.save(savedLock);

        // Then
        assertThat(updatedLock.getFailedAttempts()).isEqualTo(5);
        assertThat(updatedLock.getLockUntil()).isNotNull();
        assertThat(updatedLock.getUsername()).isEqualTo("testuser"); // Should remain unchanged
    }

    @Test
    void findById_WhenLockExists_ShouldReturnLock() {
        // Given
        LoginLock savedLock = entityManager.persistAndFlush(testLoginLock);

        // When
        Optional<LoginLock> result = loginLockRepository.findById(savedLock.getId());

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(savedLock.getId());
        assertThat(result.get().getUsername()).isEqualTo("testuser");
    }

    @Test
    void findById_WhenLockDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<LoginLock> result = loginLockRepository.findById(999L);

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findAll_ShouldReturnAllLocks() {
        // Given
        LoginLock lock1 = LoginLock.builder()
                .username("user1")
                .failedAttempts(2)
                .lockUntil(LocalDateTime.now().plusMinutes(10))
                .build();

        LoginLock lock2 = LoginLock.builder()
                .username("user2")
                .failedAttempts(1)
                .build();

        entityManager.persistAndFlush(lock1);
        entityManager.persistAndFlush(lock2);

        // When
        List<LoginLock> allLocks = loginLockRepository.findAll();

        // Then
        assertThat(allLocks).hasSize(2);
        assertThat(allLocks).extracting("username")
                .containsExactlyInAnyOrder("user1", "user2");
    }

    @Test
    void count_ShouldReturnCorrectCount() {
        // Given
        entityManager.persistAndFlush(testLoginLock);

        LoginLock secondLock = LoginLock.builder()
                .username("user2")
                .failedAttempts(1)
                .build();
        entityManager.persistAndFlush(secondLock);

        // When
        long count = loginLockRepository.count();

        // Then
        assertThat(count).isEqualTo(2);
    }

    @Test
    void save_WithoutLockUntil_ShouldPersistSuccessfully() {
        // Given
        LoginLock lockWithoutLockUntil = LoginLock.builder()
                .username("testuser2")
                .failedAttempts(1)
                .lockUntil(null)
                .build();

        // When
        LoginLock savedLock = loginLockRepository.save(lockWithoutLockUntil);

        // Then
        assertThat(savedLock.getId()).isNotNull();
        assertThat(savedLock.getUsername()).isEqualTo("testuser2");
        assertThat(savedLock.getFailedAttempts()).isEqualTo(1);
        assertThat(savedLock.getLockUntil()).isNull();
    }

    @Test
    void save_WithZeroFailedAttempts_ShouldPersistSuccessfully() {
        // Given
        LoginLock lockWithZeroAttempts = LoginLock.builder()
                .username("testuser3")
                .failedAttempts(0)
                .build();

        // When
        LoginLock savedLock = loginLockRepository.save(lockWithZeroAttempts);

        // Then
        assertThat(savedLock.getId()).isNotNull();
        assertThat(savedLock.getUsername()).isEqualTo("testuser3");
        assertThat(savedLock.getFailedAttempts()).isEqualTo(0);
    }

    @Test
    void existsById_WhenLockExists_ShouldReturnTrue() {
        // Given
        LoginLock savedLock = entityManager.persistAndFlush(testLoginLock);

        // When
        boolean exists = loginLockRepository.existsById(savedLock.getId());

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void existsById_WhenLockDoesNotExist_ShouldReturnFalse() {
        // When
        boolean exists = loginLockRepository.existsById(999L);

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    void deleteById_WhenLockExists_ShouldRemoveLock() {
        // Given
        LoginLock savedLock = entityManager.persistAndFlush(testLoginLock);
        Long lockId = savedLock.getId();

        // When
        loginLockRepository.deleteById(lockId);
        entityManager.flush();

        // Then
        Optional<LoginLock> result = loginLockRepository.findById(lockId);
        assertThat(result).isEmpty();
    }
}