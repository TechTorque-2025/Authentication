package com.techtorque.auth_service.service;

import com.techtorque.auth_service.entity.RefreshToken;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.entity.VerificationToken;
import com.techtorque.auth_service.repository.RefreshTokenRepository;
import com.techtorque.auth_service.repository.VerificationTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service for managing verification and refresh tokens
 */
@Service
@Transactional
public class TokenService {
    
    @Autowired
    private VerificationTokenRepository verificationTokenRepository;
    
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    
    @Value("${app.token.verification.expiry-hours:24}")
    private int verificationExpiryHours;
    
    @Value("${app.token.password-reset.expiry-hours:1}")
    private int passwordResetExpiryHours;
    
    @Value("${app.token.refresh.expiry-days:7}")
    private int refreshTokenExpiryDays;
    
    /**
     * Create email verification token
     */
    public String createVerificationToken(User user) {
        // Delete any existing verification tokens for this user
        verificationTokenRepository.findByUserAndTokenType(user, VerificationToken.TokenType.EMAIL_VERIFICATION)
            .ifPresent(verificationTokenRepository::delete);
        
        String token = UUID.randomUUID().toString();
        
        VerificationToken verificationToken = VerificationToken.builder()
                .token(token)
                .user(user)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .createdAt(LocalDateTime.now())
                .expiryDate(LocalDateTime.now().plusHours(verificationExpiryHours))
                .build();
        
        verificationTokenRepository.save(verificationToken);
        return token;
    }
    
    /**
     * Create password reset token
     */
    public String createPasswordResetToken(User user) {
        // Delete any existing password reset tokens for this user
        verificationTokenRepository.findByUserAndTokenType(user, VerificationToken.TokenType.PASSWORD_RESET)
            .ifPresent(verificationTokenRepository::delete);
        
        String token = UUID.randomUUID().toString();
        
        VerificationToken resetToken = VerificationToken.builder()
                .token(token)
                .user(user)
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .createdAt(LocalDateTime.now())
                .expiryDate(LocalDateTime.now().plusHours(passwordResetExpiryHours))
                .build();
        
        verificationTokenRepository.save(resetToken);
        return token;
    }
    
    /**
     * Validate and get verification token
     */
    public VerificationToken validateToken(String token, VerificationToken.TokenType tokenType) {
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));
        
        if (verificationToken.getTokenType() != tokenType) {
            throw new RuntimeException("Invalid token type");
        }
        
        if (verificationToken.isUsed()) {
            throw new RuntimeException("Token has already been used");
        }
        
        if (verificationToken.isExpired()) {
            throw new RuntimeException("Token has expired");
        }
        
        return verificationToken;
    }
    
    /**
     * Mark token as used
     */
    public void markTokenAsUsed(VerificationToken token) {
        token.setUsedAt(LocalDateTime.now());
        verificationTokenRepository.save(token);
    }
    
    /**
     * Create refresh token
     */
    public String createRefreshToken(User user, String ipAddress, String userAgent) {
        String token = UUID.randomUUID().toString();
        
        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .user(user)
                .createdAt(LocalDateTime.now())
                .expiryDate(LocalDateTime.now().plusDays(refreshTokenExpiryDays))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();
        
        refreshTokenRepository.save(refreshToken);
        return token;
    }
    
    /**
     * Validate refresh token
     */
    public RefreshToken validateRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        
        if (refreshToken.isRevoked()) {
            throw new RuntimeException("Refresh token has been revoked");
        }
        
        if (refreshToken.isExpired()) {
            throw new RuntimeException("Refresh token has expired");
        }
        
        return refreshToken;
    }
    
    /**
     * Revoke refresh token
     */
    public void revokeRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        
        refreshToken.setRevokedAt(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);
    }
    
    /**
     * Revoke all refresh tokens for a user
     */
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.deleteByUser(user);
    }
    
    /**
     * Clean up expired tokens
     */
    public void cleanupExpiredTokens() {
        refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
    }
}
