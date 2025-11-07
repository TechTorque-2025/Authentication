package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.UserPreferences;
import com.techtorque.auth_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserPreferencesRepository extends JpaRepository<UserPreferences, String> {
    Optional<UserPreferences> findByUser(User user);
    void deleteByUser(User user);
}
