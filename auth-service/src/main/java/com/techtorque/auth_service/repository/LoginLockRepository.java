package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.LoginLock;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface LoginLockRepository extends JpaRepository<LoginLock, Long> {
    Optional<LoginLock> findByUsername(String username);
}
