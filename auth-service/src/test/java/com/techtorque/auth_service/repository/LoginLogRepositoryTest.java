package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.LoginLog;
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
 * Comprehensive test class for LoginLogRepository
 * Tests all repository methods, edge cases, and database constraints
 */
@DataJpaTest
@ActiveProfiles("test")
class LoginLogRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private LoginLogRepository loginLogRepository;

    private LoginLog testLoginLog;

    @BeforeEach
    void setUp() {
        testLoginLog = LoginLog.builder()
                .username("testuser")
                .success(true)
                .ipAddress("192.168.1.1")
                .userAgent("Mozilla/5.0 Test Browser")
                .createdAt(LocalDateTime.now())
                .build();
    }

    @Test
    void save_WhenValidLoginLog_ShouldPersistSuccessfully() {
        // When
        LoginLog savedLog = loginLogRepository.save(testLoginLog);

        // Then
        assertThat(savedLog.getId()).isNotNull();
        assertThat(savedLog.getUsername()).isEqualTo("testuser");
        assertThat(savedLog.getSuccess()).isTrue();
        assertThat(savedLog.getIpAddress()).isEqualTo("192.168.1.1");
        assertThat(savedLog.getUserAgent()).isEqualTo("Mozilla/5.0 Test Browser");
        assertThat(savedLog.getCreatedAt()).isNotNull();
    }

    @Test
    void save_WithFailedLogin_ShouldPersistSuccessfully() {
        // Given
        LoginLog failedLog = LoginLog.builder()
                .username("testuser")
                .success(false)
                .ipAddress("192.168.1.2")
                .userAgent("Chrome Test")
                .createdAt(LocalDateTime.now())
                .build();

        // When
        LoginLog savedLog = loginLogRepository.save(failedLog);

        // Then
        assertThat(savedLog.getId()).isNotNull();
        assertThat(savedLog.getUsername()).isEqualTo("testuser");
        assertThat(savedLog.getSuccess()).isFalse();
        assertThat(savedLog.getIpAddress()).isEqualTo("192.168.1.2");
        assertThat(savedLog.getUserAgent()).isEqualTo("Chrome Test");
    }

    @Test
    @Transactional
    void deleteByUsername_WhenUserHasLogs_ShouldDeleteAllUserLogs() {
        // Given
        LoginLog log1 = LoginLog.builder()
                .username("testuser")
                .success(true)
                .ipAddress("192.168.1.1")
                .userAgent("Browser 1")
                .createdAt(LocalDateTime.now())
                .build();

        LoginLog log2 = LoginLog.builder()
                .username("testuser")
                .success(false)
                .ipAddress("192.168.1.2")
                .userAgent("Browser 2")
                .createdAt(LocalDateTime.now())
                .build();

        LoginLog anotherUserLog = LoginLog.builder()
                .username("anotheruser")
                .success(true)
                .ipAddress("192.168.1.3")
                .userAgent("Browser 3")
                .createdAt(LocalDateTime.now())
                .build();

        entityManager.persistAndFlush(log1);
        entityManager.persistAndFlush(log2);
        entityManager.persistAndFlush(anotherUserLog);

        // When
        loginLogRepository.deleteByUsername("testuser");
        entityManager.flush();

        // Then
        List<LoginLog> remainingLogs = loginLogRepository.findAll();
        assertThat(remainingLogs).hasSize(1);
        assertThat(remainingLogs.get(0).getUsername()).isEqualTo("anotheruser");
    }

    @Test
    void findById_WhenLogExists_ShouldReturnLog() {
        // Given
        LoginLog savedLog = entityManager.persistAndFlush(testLoginLog);

        // When
        Optional<LoginLog> result = loginLogRepository.findById(savedLog.getId());

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(savedLog.getId());
        assertThat(result.get().getUsername()).isEqualTo("testuser");
    }

    @Test
    void findById_WhenLogDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<LoginLog> result = loginLogRepository.findById(999L);

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findAll_ShouldReturnAllLogs() {
        // Given
        LoginLog log1 = LoginLog.builder()
                .username("user1")
                .success(true)
                .ipAddress("192.168.1.1")
                .userAgent("Browser 1")
                .createdAt(LocalDateTime.now())
                .build();

        LoginLog log2 = LoginLog.builder()
                .username("user2")
                .success(false)
                .ipAddress("192.168.1.2")
                .userAgent("Browser 2")
                .createdAt(LocalDateTime.now())
                .build();

        entityManager.persistAndFlush(log1);
        entityManager.persistAndFlush(log2);

        // When
        List<LoginLog> allLogs = loginLogRepository.findAll();

        // Then
        assertThat(allLogs).hasSize(2);
        assertThat(allLogs).extracting("username")
                .containsExactlyInAnyOrder("user1", "user2");
    }

    @Test
    void count_ShouldReturnCorrectCount() {
        // Given
        entityManager.persistAndFlush(testLoginLog);

        LoginLog secondLog = LoginLog.builder()
                .username("user2")
                .success(false)
                .ipAddress("192.168.1.2")
                .userAgent("Browser 2")
                .createdAt(LocalDateTime.now())
                .build();
        entityManager.persistAndFlush(secondLog);

        // When
        long count = loginLogRepository.count();

        // Then
        assertThat(count).isEqualTo(2);
    }

    @Test
    void save_WithNullOptionalFields_ShouldPersistSuccessfully() {
        // Given
        LoginLog logWithNulls = LoginLog.builder()
                .username("testuser")
                .success(true)
                .ipAddress(null)
                .userAgent(null)
                .createdAt(LocalDateTime.now())
                .build();

        // When
        LoginLog savedLog = loginLogRepository.save(logWithNulls);

        // Then
        assertThat(savedLog.getId()).isNotNull();
        assertThat(savedLog.getUsername()).isEqualTo("testuser");
        assertThat(savedLog.getSuccess()).isTrue();
        assertThat(savedLog.getIpAddress()).isNull();
        assertThat(savedLog.getUserAgent()).isNull();
    }

    @Test
    void existsById_WhenLogExists_ShouldReturnTrue() {
        // Given
        LoginLog savedLog = entityManager.persistAndFlush(testLoginLog);

        // When
        boolean exists = loginLogRepository.existsById(savedLog.getId());

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void existsById_WhenLogDoesNotExist_ShouldReturnFalse() {
        // When
        boolean exists = loginLogRepository.existsById(999L);

        // Then
        assertThat(exists).isFalse();
    }
}