package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.LoginLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginLogRepository extends JpaRepository<LoginLog, Long> {
    void deleteByUsername(String username);
}
