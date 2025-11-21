package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.Role;
import com.techtorque.auth_service.entity.RoleName;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.entity.VerificationToken;
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
 * Comprehensive test class for VerificationTokenRepository
 * Tests all repository methods, edge cases, and database constraints
 */
@DataJpaTest
@ActiveProfiles("test")
class VerificationTokenRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;

    private User testUser;
    private VerificationToken testToken;

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

        // Create test verification token
        testToken = VerificationToken.builder()
                .token("test-verification-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(1))
                .createdAt(LocalDateTime.now())
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .build();
    }

    @Test
    void save_WhenValidToken_ShouldPersistSuccessfully() {
        // When
        VerificationToken savedToken = verificationTokenRepository.save(testToken);

        // Then
        assertThat(savedToken.getId()).isNotNull();
        assertThat(savedToken.getToken()).isEqualTo("test-verification-token");
        assertThat(savedToken.getUser().getId()).isEqualTo(testUser.getId());
        assertThat(savedToken.getExpiryDate()).isNotNull();
        assertThat(savedToken.getCreatedAt()).isNotNull();
        assertThat(savedToken.getTokenType()).isEqualTo(VerificationToken.TokenType.EMAIL_VERIFICATION);
        assertThat(savedToken.getUsedAt()).isNull();
    }

    @Test
    void findByToken_WhenTokenExists_ShouldReturnToken() {
        // Given
        entityManager.persistAndFlush(testToken);

        // When
        Optional<VerificationToken> result = verificationTokenRepository.findByToken("test-verification-token");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getToken()).isEqualTo("test-verification-token");
        assertThat(result.get().getUser().getId()).isEqualTo(testUser.getId());
        assertThat(result.get().getTokenType()).isEqualTo(VerificationToken.TokenType.EMAIL_VERIFICATION);
    }

    @Test
    void findByToken_WhenTokenDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<VerificationToken> result = verificationTokenRepository.findByToken("non-existent-token");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findByUserAndTokenType_WhenTokenExists_ShouldReturnToken() {
        // Given
        entityManager.persistAndFlush(testToken);

        // When
        Optional<VerificationToken> result = verificationTokenRepository
                .findByUserAndTokenType(testUser, VerificationToken.TokenType.EMAIL_VERIFICATION);

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getUser().getId()).isEqualTo(testUser.getId());
        assertThat(result.get().getTokenType()).isEqualTo(VerificationToken.TokenType.EMAIL_VERIFICATION);
    }

    @Test
    void findByUserAndTokenType_WhenTokenDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<VerificationToken> result = verificationTokenRepository
                .findByUserAndTokenType(testUser, VerificationToken.TokenType.PASSWORD_RESET);

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findByUserAndTokenType_WhenDifferentTokenType_ShouldReturnEmpty() {
        // Given
        entityManager.persistAndFlush(testToken);

        // When
        Optional<VerificationToken> result = verificationTokenRepository
                .findByUserAndTokenType(testUser, VerificationToken.TokenType.PASSWORD_RESET);

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    @Transactional
    void deleteByUser_WhenUserHasTokens_ShouldDeleteAllUserTokens() {
        // Given
        VerificationToken emailToken = VerificationToken.builder()
                .token("email-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(1))
                .createdAt(LocalDateTime.now())
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .build();

        VerificationToken passwordToken = VerificationToken.builder()
                .token("password-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusHours(1))
                .createdAt(LocalDateTime.now())
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .build();

        entityManager.persistAndFlush(emailToken);
        entityManager.persistAndFlush(passwordToken);

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

        VerificationToken anotherUserToken = VerificationToken.builder()
                .token("another-token")
                .user(anotherUser)
                .expiryDate(LocalDateTime.now().plusDays(1))
                .createdAt(LocalDateTime.now())
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .build();
        entityManager.persistAndFlush(anotherUserToken);

        // When
        verificationTokenRepository.deleteByUser(testUser);
        entityManager.flush();

        // Then
        assertThat(verificationTokenRepository.findByToken("email-token")).isEmpty();
        assertThat(verificationTokenRepository.findByToken("password-token")).isEmpty();
        assertThat(verificationTokenRepository.findByToken("another-token")).isPresent();
    }

    @Test
    void isExpired_WhenTokenIsExpired_ShouldReturnTrue() {
        // Given
        VerificationToken expiredToken = VerificationToken.builder()
                .token("expired-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().minusDays(1))
                .createdAt(LocalDateTime.now().minusDays(2))
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .build();

        // When
        boolean isExpired = expiredToken.isExpired();

        // Then
        assertThat(isExpired).isTrue();
    }

    @Test
    void isExpired_WhenTokenIsNotExpired_ShouldReturnFalse() {
        // Given
        VerificationToken validToken = VerificationToken.builder()
                .token("valid-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(1))
                .createdAt(LocalDateTime.now())
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .build();

        // When
        boolean isExpired = validToken.isExpired();

        // Then
        assertThat(isExpired).isFalse();
    }

    @Test
    void isUsed_WhenTokenIsUsed_ShouldReturnTrue() {
        // Given
        VerificationToken usedToken = VerificationToken.builder()
                .token("used-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(1))
                .createdAt(LocalDateTime.now())
                .usedAt(LocalDateTime.now())
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .build();

        // When
        boolean isUsed = usedToken.isUsed();

        // Then
        assertThat(isUsed).isTrue();
    }

    @Test
    void isUsed_WhenTokenIsNotUsed_ShouldReturnFalse() {
        // Given
        VerificationToken unusedToken = VerificationToken.builder()
                .token("unused-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(1))
                .createdAt(LocalDateTime.now())
                .usedAt(null)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .build();

        // When
        boolean isUsed = unusedToken.isUsed();

        // Then
        assertThat(isUsed).isFalse();
    }

    @Test
    void save_WithPasswordResetType_ShouldPersistSuccessfully() {
        // Given
        VerificationToken passwordResetToken = VerificationToken.builder()
                .token("password-reset-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusHours(1))
                .createdAt(LocalDateTime.now())
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .build();

        // When
        VerificationToken savedToken = verificationTokenRepository.save(passwordResetToken);

        // Then
        assertThat(savedToken.getId()).isNotNull();
        assertThat(savedToken.getToken()).isEqualTo("password-reset-token");
        assertThat(savedToken.getTokenType()).isEqualTo(VerificationToken.TokenType.PASSWORD_RESET);
    }

    @Test
    void findById_WhenTokenExists_ShouldReturnToken() {
        // Given
        VerificationToken savedToken = entityManager.persistAndFlush(testToken);

        // When
        Optional<VerificationToken> result = verificationTokenRepository.findById(savedToken.getId());

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(savedToken.getId());
        assertThat(result.get().getToken()).isEqualTo("test-verification-token");
    }

    @Test
    void findById_WhenTokenDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<VerificationToken> result = verificationTokenRepository.findById("non-existent-id");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void update_WhenTokenIsUsed_ShouldUpdateUsedAt() {
        // Given
        VerificationToken savedToken = entityManager.persistAndFlush(testToken);
        entityManager.detach(savedToken);

        // When
        LocalDateTime usedTime = LocalDateTime.now();
        savedToken.setUsedAt(usedTime);
        VerificationToken updatedToken = verificationTokenRepository.save(savedToken);

        // Then
        assertThat(updatedToken.getUsedAt()).isEqualTo(usedTime);
        assertThat(updatedToken.isUsed()).isTrue();
    }

    @Test
    void findAll_ShouldReturnAllTokens() {
        // Given
        VerificationToken emailToken = VerificationToken.builder()
                .token("email-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(1))
                .createdAt(LocalDateTime.now())
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .build();

        VerificationToken passwordToken = VerificationToken.builder()
                .token("password-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusHours(1))
                .createdAt(LocalDateTime.now())
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .build();

        entityManager.persistAndFlush(emailToken);
        entityManager.persistAndFlush(passwordToken);

        // When
        var allTokens = verificationTokenRepository.findAll();

        // Then
        assertThat(allTokens).hasSize(2);
        assertThat(allTokens).extracting("token")
                .containsExactlyInAnyOrder("email-token", "password-token");
        assertThat(allTokens).extracting("tokenType")
                .containsExactlyInAnyOrder(
                        VerificationToken.TokenType.EMAIL_VERIFICATION,
                        VerificationToken.TokenType.PASSWORD_RESET);
    }

    @Test
    void count_ShouldReturnCorrectCount() {
        // Given
        entityManager.persistAndFlush(testToken);

        VerificationToken secondToken = VerificationToken.builder()
                .token("second-token")
                .user(testUser)
                .expiryDate(LocalDateTime.now().plusDays(1))
                .createdAt(LocalDateTime.now())
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .build();
        entityManager.persistAndFlush(secondToken);

        // When
        long count = verificationTokenRepository.count();

        // Then
        assertThat(count).isEqualTo(2);
    }
}