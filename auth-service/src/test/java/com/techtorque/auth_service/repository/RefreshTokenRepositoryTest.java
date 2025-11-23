package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.RefreshToken;
import com.techtorque.auth_service.entity.Role;
import com.techtorque.auth_service.entity.RoleName;
import com.techtorque.auth_service.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Comprehensive test class for RefreshTokenRepository
 * Tests all repository methods, edge cases, and database constraints
 */
@DataJpaTest
@ActiveProfiles("test")
class RefreshTokenRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private User testUser;
    private RefreshToken testToken;

    @BeforeEach
    void setUp() {
        // Create test role
        Role testRole = Role.builder()
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
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();
        testUser.addRole(testRole);
        testUser = entityManager.persistAndFlush(testUser);

        // Create test refresh token
        testToken = RefreshToken.builder()
                .token("test-refresh-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .createdAt(LocalDateTime.now())
                .ipAddress("192.168.1.1")
                .userAgent("Test User Agent")
                .build();
    }

    @Test
    void save_WhenValidToken_ShouldPersistSuccessfully() {
        // When
        RefreshToken savedToken = refreshTokenRepository.save(testToken);

        // Then
        assertThat(savedToken.getId()).isNotNull();
        assertThat(savedToken.getToken()).isEqualTo("test-refresh-token");
        assertThat(savedToken.getUser().getId()).isEqualTo(testUser.getId());
        assertThat(savedToken.getExpiryDate()).isNotNull();
        assertThat(savedToken.getCreatedAt()).isNotNull();
        assertThat(savedToken.getIpAddress()).isEqualTo("192.168.1.1");
        assertThat(savedToken.getUserAgent()).isEqualTo("Test User Agent");
        assertThat(savedToken.getRevokedAt()).isNull();
    }

    @Test
    void findByToken_WhenTokenExists_ShouldReturnToken() {
        // Given
        entityManager.persistAndFlush(testToken);

        // When
        Optional<RefreshToken> result = refreshTokenRepository.findByToken("test-refresh-token");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getToken()).isEqualTo("test-refresh-token");
        assertThat(result.get().getUser().getId()).isEqualTo(testUser.getId());
        assertThat(result.get().getIpAddress()).isEqualTo("192.168.1.1");
    }

    @Test
    void findByToken_WhenTokenDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<RefreshToken> result = refreshTokenRepository.findByToken("non-existent-token");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    @Transactional
    void deleteByUser_WhenUserHasTokens_ShouldDeleteAllUserTokens() {
        // Given
        RefreshToken token1 = RefreshToken.builder()
                .token("token-1")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .createdAt(LocalDateTime.now())
                .build();

        RefreshToken token2 = RefreshToken.builder()
                .token("token-2")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .createdAt(LocalDateTime.now())
                .build();

        entityManager.persistAndFlush(token1);
        entityManager.persistAndFlush(token2);

        // Create another user with a token to ensure we only delete current user's
        // tokens
        User anotherUser = User.builder()
                .username("anotheruser")
                .password("password")
                .email("another@example.com")
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();
        anotherUser = entityManager.persistAndFlush(anotherUser);

        RefreshToken anotherUserToken = RefreshToken.builder()
                .token("another-token")
                .user(anotherUser)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .createdAt(LocalDateTime.now())
                .build();
        entityManager.persistAndFlush(anotherUserToken);

        // When
        refreshTokenRepository.deleteByUser(testUser);
        entityManager.flush();

        // Then
        assertThat(refreshTokenRepository.findByToken("token-1")).isEmpty();
        assertThat(refreshTokenRepository.findByToken("token-2")).isEmpty();
        assertThat(refreshTokenRepository.findByToken("another-token")).isPresent();
    }

    @Test
    @Transactional
    void deleteExpiredTokens_WhenExpiredTokensExist_ShouldDeleteOnlyExpiredTokens() {
        // Given
        RefreshToken expiredToken1 = RefreshToken.builder()
                .token("expired-token-1")
                .user(testUser)
                .expiryDate(LocalDateTime.now().minusDays(1)) // Expired
                .createdAt(LocalDateTime.now().minusDays(2))
                .build();

        RefreshToken expiredToken2 = RefreshToken.builder()
                .token("expired-token-2")
                .user(testUser)
                .expiryDate(LocalDateTime.now().minusHours(1)) // Expired
                .createdAt(LocalDateTime.now().minusDays(1))
                .build();

        RefreshToken validToken = RefreshToken.builder()
                .token("valid-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(7)) // Not expired
                .createdAt(LocalDateTime.now())
                .build();

        entityManager.persistAndFlush(expiredToken1);
        entityManager.persistAndFlush(expiredToken2);
        entityManager.persistAndFlush(validToken);

        // When
        refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
        entityManager.flush();

        // Then
        assertThat(refreshTokenRepository.findByToken("expired-token-1")).isEmpty();
        assertThat(refreshTokenRepository.findByToken("expired-token-2")).isEmpty();
        assertThat(refreshTokenRepository.findByToken("valid-token")).isPresent();
    }

    @Test
    void isExpired_WhenTokenIsExpired_ShouldReturnTrue() {
        // Given
        RefreshToken expiredToken = RefreshToken.builder()
                .token("expired-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().minusDays(1))
                .createdAt(LocalDateTime.now().minusDays(2))
                .build();

        // When
        boolean isExpired = expiredToken.isExpired();

        // Then
        assertThat(isExpired).isTrue();
    }

    @Test
    void isExpired_WhenTokenIsNotExpired_ShouldReturnFalse() {
        // Given
        RefreshToken validToken = RefreshToken.builder()
                .token("valid-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .createdAt(LocalDateTime.now())
                .build();

        // When
        boolean isExpired = validToken.isExpired();

        // Then
        assertThat(isExpired).isFalse();
    }

    @Test
    void isRevoked_WhenTokenIsRevoked_ShouldReturnTrue() {
        // Given
        RefreshToken revokedToken = RefreshToken.builder()
                .token("revoked-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .createdAt(LocalDateTime.now())
                .revokedAt(LocalDateTime.now())
                .build();

        // When
        boolean isRevoked = revokedToken.isRevoked();

        // Then
        assertThat(isRevoked).isTrue();
    }

    @Test
    void isRevoked_WhenTokenIsNotRevoked_ShouldReturnFalse() {
        // Given
        RefreshToken activeToken = RefreshToken.builder()
                .token("active-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .createdAt(LocalDateTime.now())
                .revokedAt(null)
                .build();

        // When
        boolean isRevoked = activeToken.isRevoked();

        // Then
        assertThat(isRevoked).isFalse();
    }

    @Test
    void findById_WhenTokenExists_ShouldReturnToken() {
        // Given
        RefreshToken savedToken = entityManager.persistAndFlush(testToken);

        // When
        Optional<RefreshToken> result = refreshTokenRepository.findById(savedToken.getId());

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(savedToken.getId());
        assertThat(result.get().getToken()).isEqualTo("test-refresh-token");
    }

    @Test
    void findById_WhenTokenDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<RefreshToken> result = refreshTokenRepository.findById("non-existent-id");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void update_WhenTokenIsRevoked_ShouldUpdateRevokedAt() {
        // Given
        RefreshToken savedToken = entityManager.persistAndFlush(testToken);
        entityManager.detach(savedToken);

        // When
        LocalDateTime revokedTime = LocalDateTime.now();
        savedToken.setRevokedAt(revokedTime);
        RefreshToken updatedToken = refreshTokenRepository.save(savedToken);

        // Then
        assertThat(updatedToken.getRevokedAt()).isEqualTo(revokedTime);
        assertThat(updatedToken.isRevoked()).isTrue();
    }

    @Test
    void findAll_ShouldReturnAllTokens() {
        // Given
        RefreshToken token1 = RefreshToken.builder()
                .token("token-1")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .createdAt(LocalDateTime.now())
                .build();

        RefreshToken token2 = RefreshToken.builder()
                .token("token-2")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .createdAt(LocalDateTime.now())
                .build();

        entityManager.persistAndFlush(token1);
        entityManager.persistAndFlush(token2);

        // When
        var allTokens = refreshTokenRepository.findAll();

        // Then
        assertThat(allTokens).hasSize(2);
        assertThat(allTokens).extracting("token")
                .containsExactlyInAnyOrder("token-1", "token-2");
    }

    @Test
    void count_ShouldReturnCorrectCount() {
        // Given
        entityManager.persistAndFlush(testToken);

        RefreshToken secondToken = RefreshToken.builder()
                .token("second-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .createdAt(LocalDateTime.now())
                .build();
        entityManager.persistAndFlush(secondToken);

        // When
        long count = refreshTokenRepository.count();

        // Then
        assertThat(count).isEqualTo(2);
    }
}