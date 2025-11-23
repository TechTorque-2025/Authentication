package com.techtorque.auth_service.service;

import com.techtorque.auth_service.entity.RefreshToken;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.entity.VerificationToken;
import com.techtorque.auth_service.repository.RefreshTokenRepository;
import com.techtorque.auth_service.repository.VerificationTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive test class for TokenService
 * Tests token creation, validation, expiry, and cleanup operations
 */
@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock
    private VerificationTokenRepository verificationTokenRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private TokenService tokenService;

    private User testUser;
    private VerificationToken verificationToken;
    private RefreshToken refreshToken;

    @BeforeEach
    void setUp() {
        // Set up test configuration
        ReflectionTestUtils.setField(tokenService, "verificationExpiryHours", 24);
        ReflectionTestUtils.setField(tokenService, "passwordResetExpiryHours", 1);
        ReflectionTestUtils.setField(tokenService, "refreshTokenExpiryDays", 7);

        // Create test user
        testUser = User.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .password("encoded-password")
                .enabled(true)
                .build();

        // Create test verification token
        verificationToken = VerificationToken.builder()
                .id("token-1")
                .token("verification-token")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .createdAt(LocalDateTime.now())
                .expiryDate(LocalDateTime.now().plusHours(24))
                .build();

        // Create test refresh token
        refreshToken = RefreshToken.builder()
                .id("refresh-1")
                .token("refresh-token")
                .user(testUser)
                .createdAt(LocalDateTime.now())
                .expiryDate(LocalDateTime.now().plusDays(7))
                .ipAddress("127.0.0.1")
                .userAgent("Test-Agent")
                .build();
    }

    @Test
    void createVerificationToken_WhenValidUser_ShouldCreateAndReturnToken() {
        // Given
        when(verificationTokenRepository.findByUserAndTokenType(testUser,
                VerificationToken.TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.empty());
        when(verificationTokenRepository.save(any(VerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // When
        String result = tokenService.createVerificationToken(testUser);

        // Then
        assertThat(result).isNotNull();
        assertThat(result).hasSize(36); // UUID length
        verify(verificationTokenRepository).save(argThat(token -> token.getUser().equals(testUser) &&
                token.getTokenType().equals(VerificationToken.TokenType.EMAIL_VERIFICATION) &&
                token.getExpiryDate().isAfter(LocalDateTime.now().plusHours(23))));
    }

    @Test
    void createVerificationToken_WhenExistingTokenExists_ShouldDeleteExistingToken() {
        // Given
        VerificationToken existingToken = VerificationToken.builder()
                .token("existing-token")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .build();

        when(verificationTokenRepository.findByUserAndTokenType(testUser,
                VerificationToken.TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.of(existingToken));
        when(verificationTokenRepository.save(any(VerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // When
        String result = tokenService.createVerificationToken(testUser);

        // Then
        assertThat(result).isNotNull();
        verify(verificationTokenRepository).delete(existingToken);
        verify(verificationTokenRepository).save(any(VerificationToken.class));
    }

    @Test
    void createPasswordResetToken_WhenValidUser_ShouldCreateAndReturnToken() {
        // Given
        when(verificationTokenRepository.findByUserAndTokenType(testUser, VerificationToken.TokenType.PASSWORD_RESET))
                .thenReturn(Optional.empty());
        when(verificationTokenRepository.save(any(VerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // When
        String result = tokenService.createPasswordResetToken(testUser);

        // Then
        assertThat(result).isNotNull();
        assertThat(result).hasSize(36); // UUID length
        verify(verificationTokenRepository).save(argThat(token -> token.getUser().equals(testUser) &&
                token.getTokenType().equals(VerificationToken.TokenType.PASSWORD_RESET) &&
                token.getExpiryDate().isAfter(LocalDateTime.now().plusMinutes(30))));
    }

    @Test
    void createPasswordResetToken_WhenExistingTokenExists_ShouldDeleteExistingToken() {
        // Given
        VerificationToken existingToken = VerificationToken.builder()
                .token("existing-reset-token")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .build();

        when(verificationTokenRepository.findByUserAndTokenType(testUser, VerificationToken.TokenType.PASSWORD_RESET))
                .thenReturn(Optional.of(existingToken));
        when(verificationTokenRepository.save(any(VerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // When
        String result = tokenService.createPasswordResetToken(testUser);

        // Then
        assertThat(result).isNotNull();
        verify(verificationTokenRepository).delete(existingToken);
        verify(verificationTokenRepository).save(any(VerificationToken.class));
    }

    @Test
    void validateToken_WhenValidToken_ShouldReturnToken() {
        // Given
        when(verificationTokenRepository.findByToken("verification-token")).thenReturn(Optional.of(verificationToken));

        // When
        VerificationToken result = tokenService.validateToken("verification-token",
                VerificationToken.TokenType.EMAIL_VERIFICATION);

        // Then
        assertThat(result).isEqualTo(verificationToken);
    }

    @Test
    void validateToken_WhenTokenNotFound_ShouldThrowRuntimeException() {
        // Given
        when(verificationTokenRepository.findByToken("invalid-token")).thenReturn(Optional.empty());

        // When/Then
        assertThatThrownBy(
                () -> tokenService.validateToken("invalid-token", VerificationToken.TokenType.EMAIL_VERIFICATION))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Invalid token");
    }

    @Test
    void validateToken_WhenWrongTokenType_ShouldThrowRuntimeException() {
        // Given
        when(verificationTokenRepository.findByToken("verification-token")).thenReturn(Optional.of(verificationToken));

        // When/Then
        assertThatThrownBy(
                () -> tokenService.validateToken("verification-token", VerificationToken.TokenType.PASSWORD_RESET))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Invalid token type");
    }

    @Test
    void validateToken_WhenTokenAlreadyUsed_ShouldThrowRuntimeException() {
        // Given
        verificationToken.setUsedAt(LocalDateTime.now());
        when(verificationTokenRepository.findByToken("verification-token")).thenReturn(Optional.of(verificationToken));

        // When/Then
        assertThatThrownBy(
                () -> tokenService.validateToken("verification-token", VerificationToken.TokenType.EMAIL_VERIFICATION))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Token has already been used");
    }

    @Test
    void validateToken_WhenTokenExpired_ShouldThrowRuntimeException() {
        // Given
        verificationToken.setExpiryDate(LocalDateTime.now().minusHours(1));
        when(verificationTokenRepository.findByToken("verification-token")).thenReturn(Optional.of(verificationToken));

        // When/Then
        assertThatThrownBy(
                () -> tokenService.validateToken("verification-token", VerificationToken.TokenType.EMAIL_VERIFICATION))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Token has expired");
    }

    @Test
    void markTokenAsUsed_ShouldSetUsedAtTimestamp() {
        // Given
        when(verificationTokenRepository.save(verificationToken)).thenReturn(verificationToken);

        // When
        tokenService.markTokenAsUsed(verificationToken);

        // Then
        assertThat(verificationToken.getUsedAt()).isNotNull();
        assertThat(verificationToken.getUsedAt()).isBefore(LocalDateTime.now().plusSeconds(1));
        verify(verificationTokenRepository).save(verificationToken);
    }

    @Test
    void createRefreshToken_WhenValidUser_ShouldCreateAndReturnToken() {
        // Given
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        String result = tokenService.createRefreshToken(testUser, "192.168.1.1", "Mozilla/5.0");

        // Then
        assertThat(result).isNotNull();
        assertThat(result).hasSize(36); // UUID length
        verify(refreshTokenRepository).save(argThat(token -> token.getUser().equals(testUser) &&
                token.getIpAddress().equals("192.168.1.1") &&
                token.getUserAgent().equals("Mozilla/5.0") &&
                token.getExpiryDate().isAfter(LocalDateTime.now().plusDays(6))));
    }

    @Test
    void createRefreshToken_WhenNullIpAndUserAgent_ShouldCreateTokenWithNulls() {
        // Given
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        String result = tokenService.createRefreshToken(testUser, null, null);

        // Then
        assertThat(result).isNotNull();
        verify(refreshTokenRepository).save(argThat(token -> token.getUser().equals(testUser) &&
                token.getIpAddress() == null &&
                token.getUserAgent() == null));
    }

    @Test
    void validateRefreshToken_WhenValidToken_ShouldReturnToken() {
        // Given
        when(refreshTokenRepository.findByToken("refresh-token")).thenReturn(Optional.of(refreshToken));

        // When
        RefreshToken result = tokenService.validateRefreshToken("refresh-token");

        // Then
        assertThat(result).isEqualTo(refreshToken);
    }

    @Test
    void validateRefreshToken_WhenTokenNotFound_ShouldThrowRuntimeException() {
        // Given
        when(refreshTokenRepository.findByToken("invalid-token")).thenReturn(Optional.empty());

        // When/Then
        assertThatThrownBy(() -> tokenService.validateRefreshToken("invalid-token"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Invalid refresh token");
    }

    @Test
    void validateRefreshToken_WhenTokenRevoked_ShouldThrowRuntimeException() {
        // Given
        refreshToken.setRevokedAt(LocalDateTime.now());
        when(refreshTokenRepository.findByToken("refresh-token")).thenReturn(Optional.of(refreshToken));

        // When/Then
        assertThatThrownBy(() -> tokenService.validateRefreshToken("refresh-token"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Refresh token has been revoked");
    }

    @Test
    void validateRefreshToken_WhenTokenExpired_ShouldThrowRuntimeException() {
        // Given
        refreshToken.setExpiryDate(LocalDateTime.now().minusDays(1));
        when(refreshTokenRepository.findByToken("refresh-token")).thenReturn(Optional.of(refreshToken));

        // When/Then
        assertThatThrownBy(() -> tokenService.validateRefreshToken("refresh-token"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Refresh token has expired");
    }

    @Test
    void revokeRefreshToken_WhenValidToken_ShouldSetRevokedAt() {
        // Given
        when(refreshTokenRepository.findByToken("refresh-token")).thenReturn(Optional.of(refreshToken));
        when(refreshTokenRepository.save(refreshToken)).thenReturn(refreshToken);

        // When
        tokenService.revokeRefreshToken("refresh-token");

        // Then
        assertThat(refreshToken.getRevokedAt()).isNotNull();
        assertThat(refreshToken.getRevokedAt()).isBefore(LocalDateTime.now().plusSeconds(1));
        verify(refreshTokenRepository).save(refreshToken);
    }

    @Test
    void revokeRefreshToken_WhenTokenNotFound_ShouldThrowRuntimeException() {
        // Given
        when(refreshTokenRepository.findByToken("invalid-token")).thenReturn(Optional.empty());

        // When/Then
        assertThatThrownBy(() -> tokenService.revokeRefreshToken("invalid-token"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Invalid refresh token");
    }

    @Test
    void revokeAllUserTokens_ShouldDeleteAllUserTokens() {
        // When
        tokenService.revokeAllUserTokens(testUser);

        // Then
        verify(refreshTokenRepository).deleteByUser(testUser);
    }

    @Test
    void cleanupExpiredTokens_ShouldDeleteExpiredTokens() {
        // When
        tokenService.cleanupExpiredTokens();

        // Then
        verify(refreshTokenRepository).deleteExpiredTokens(any(LocalDateTime.class));
    }

    @Test
    void createVerificationToken_WithCustomExpiryHours_ShouldUseConfiguredExpiry() {
        // Given
        ReflectionTestUtils.setField(tokenService, "verificationExpiryHours", 48);
        when(verificationTokenRepository.findByUserAndTokenType(testUser,
                VerificationToken.TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.empty());
        when(verificationTokenRepository.save(any(VerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // When
        String result = tokenService.createVerificationToken(testUser);

        // Then
        assertThat(result).isNotNull();
        verify(verificationTokenRepository)
                .save(argThat(token -> token.getExpiryDate().isAfter(LocalDateTime.now().plusHours(47))));
    }

    @Test
    void createPasswordResetToken_WithCustomExpiryHours_ShouldUseConfiguredExpiry() {
        // Given
        ReflectionTestUtils.setField(tokenService, "passwordResetExpiryHours", 2);
        when(verificationTokenRepository.findByUserAndTokenType(testUser, VerificationToken.TokenType.PASSWORD_RESET))
                .thenReturn(Optional.empty());
        when(verificationTokenRepository.save(any(VerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // When
        String result = tokenService.createPasswordResetToken(testUser);

        // Then
        assertThat(result).isNotNull();
        verify(verificationTokenRepository).save(
                argThat(token -> token.getExpiryDate().isAfter(LocalDateTime.now().plusHours(1).plusMinutes(30))));
    }

    @Test
    void createRefreshToken_WithCustomExpiryDays_ShouldUseConfiguredExpiry() {
        // Given
        ReflectionTestUtils.setField(tokenService, "refreshTokenExpiryDays", 14);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        String result = tokenService.createRefreshToken(testUser, "127.0.0.1", "Test-Agent");

        // Then
        assertThat(result).isNotNull();
        verify(refreshTokenRepository)
                .save(argThat(token -> token.getExpiryDate().isAfter(LocalDateTime.now().plusDays(13))));
    }

    @Test
    void validateToken_WhenTokenJustExpired_ShouldThrowRuntimeException() {
        // Given
        verificationToken.setExpiryDate(LocalDateTime.now().minusSeconds(1));
        when(verificationTokenRepository.findByToken("verification-token")).thenReturn(Optional.of(verificationToken));

        // When/Then
        assertThatThrownBy(
                () -> tokenService.validateToken("verification-token", VerificationToken.TokenType.EMAIL_VERIFICATION))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Token has expired");
    }

    @Test
    void validateRefreshToken_WhenTokenJustExpired_ShouldThrowRuntimeException() {
        // Given
        refreshToken.setExpiryDate(LocalDateTime.now().minusSeconds(1));
        when(refreshTokenRepository.findByToken("refresh-token")).thenReturn(Optional.of(refreshToken));

        // When/Then
        assertThatThrownBy(() -> tokenService.validateRefreshToken("refresh-token"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Refresh token has expired");
    }

    @Test
    void validateToken_WhenTokenJustBeforeExpiry_ShouldReturnToken() {
        // Given
        verificationToken.setExpiryDate(LocalDateTime.now().plusSeconds(1));
        when(verificationTokenRepository.findByToken("verification-token")).thenReturn(Optional.of(verificationToken));

        // When
        VerificationToken result = tokenService.validateToken("verification-token",
                VerificationToken.TokenType.EMAIL_VERIFICATION);

        // Then
        assertThat(result).isEqualTo(verificationToken);
    }

    @Test
    void validateRefreshToken_WhenTokenJustBeforeExpiry_ShouldReturnToken() {
        // Given
        refreshToken.setExpiryDate(LocalDateTime.now().plusSeconds(1));
        when(refreshTokenRepository.findByToken("refresh-token")).thenReturn(Optional.of(refreshToken));

        // When
        RefreshToken result = tokenService.validateRefreshToken("refresh-token");

        // Then
        assertThat(result).isEqualTo(refreshToken);
    }
}
