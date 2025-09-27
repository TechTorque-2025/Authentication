package com.techtorque.auth_service.service;

import com.techtorque.auth_service.entity.LoginLock;
import com.techtorque.auth_service.entity.LoginLog;
import com.techtorque.auth_service.repository.LoginLockRepository;
import com.techtorque.auth_service.repository.LoginLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Service
public class LoginAuditService {

    @Autowired
    private LoginLockRepository loginLockRepository;

    @Autowired
    private LoginLogRepository loginLogRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void incrementFailedAttempt(String username, long lockDurationMinutes, int maxFailedAttempts) {
        LoginLock lock = loginLockRepository.findByUsername(username)
                .orElseGet(() -> LoginLock.builder().username(username).failedAttempts(0).build());

        int attempts = lock.getFailedAttempts() == null ? 0 : lock.getFailedAttempts();
        attempts++;
        lock.setFailedAttempts(attempts);
        if (attempts >= maxFailedAttempts) {
            lock.setLockUntil(LocalDateTime.now().plus(lockDurationMinutes, ChronoUnit.MINUTES));
        }

        loginLockRepository.save(lock);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void resetFailedAttempts(String username) {
        LoginLock lock = loginLockRepository.findByUsername(username)
                .orElseGet(() -> LoginLock.builder().username(username).failedAttempts(0).build());
        lock.setFailedAttempts(0);
        lock.setLockUntil(null);
        loginLockRepository.save(lock);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordLogin(String username, boolean success, String ip, String userAgent) {
        LoginLog log = LoginLog.builder()
                .username(username)
                .success(success)
                .ipAddress(ip)
                .userAgent(userAgent)
                .createdAt(LocalDateTime.now())
                .build();
        loginLogRepository.save(log);
    }
}
