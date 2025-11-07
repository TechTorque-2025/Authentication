package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.VerificationToken;
import com.techtorque.auth_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, String> {
    Optional<VerificationToken> findByToken(String token);
    Optional<VerificationToken> findByUserAndTokenType(User user, VerificationToken.TokenType tokenType);
    void deleteByUser(User user);
}
