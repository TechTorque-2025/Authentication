package com.techtorque.auth_service.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "login_locks")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginLock {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(name = "failed_attempts", nullable = false)
    @Builder.Default
    private Integer failedAttempts = 0;

    @Column(name = "lock_until")
    private LocalDateTime lockUntil;
}
