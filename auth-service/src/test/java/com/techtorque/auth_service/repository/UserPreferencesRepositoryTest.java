package com.techtorque.auth_service.repository;

import com.techtorque.auth_service.entity.Role;
import com.techtorque.auth_service.entity.RoleName;
import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.entity.UserPreferences;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Comprehensive test class for UserPreferencesRepository
 * Tests all repository methods, edge cases, and database constraints
 */
@DataJpaTest
@ActiveProfiles("test")
class UserPreferencesRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserPreferencesRepository userPreferencesRepository;

    private User testUser;
    private UserPreferences testPreferences;

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

        // Create test user preferences
        testPreferences = UserPreferences.builder()
                .user(testUser)
                .emailNotifications(true)
                .smsNotifications(false)
                .pushNotifications(true)
                .language("en")
                .appointmentReminders(true)
                .serviceUpdates(true)
                .marketingEmails(false)
                .build();
    }

    @Test
    void save_WhenValidPreferences_ShouldPersistSuccessfully() {
        // When
        UserPreferences savedPreferences = userPreferencesRepository.save(testPreferences);

        // Then
        assertThat(savedPreferences.getId()).isNotNull();
        assertThat(savedPreferences.getUser().getId()).isEqualTo(testUser.getId());
        assertThat(savedPreferences.getEmailNotifications()).isTrue();
        assertThat(savedPreferences.getSmsNotifications()).isFalse();
        assertThat(savedPreferences.getPushNotifications()).isTrue();
        assertThat(savedPreferences.getLanguage()).isEqualTo("en");
        assertThat(savedPreferences.getAppointmentReminders()).isTrue();
        assertThat(savedPreferences.getServiceUpdates()).isTrue();
        assertThat(savedPreferences.getMarketingEmails()).isFalse();
    }

    @Test
    void save_WithDefaults_ShouldUseDefaultValues() {
        // Given
        UserPreferences preferencesWithDefaults = UserPreferences.builder()
                .user(testUser)
                .build();

        // When
        UserPreferences savedPreferences = userPreferencesRepository.save(preferencesWithDefaults);

        // Then
        assertThat(savedPreferences.getId()).isNotNull();
        assertThat(savedPreferences.getEmailNotifications()).isTrue(); // Default
        assertThat(savedPreferences.getSmsNotifications()).isFalse(); // Default
        assertThat(savedPreferences.getPushNotifications()).isTrue(); // Default
        assertThat(savedPreferences.getLanguage()).isEqualTo("en"); // Default
        assertThat(savedPreferences.getAppointmentReminders()).isTrue(); // Default
        assertThat(savedPreferences.getServiceUpdates()).isTrue(); // Default
        assertThat(savedPreferences.getMarketingEmails()).isFalse(); // Default
    }

    @Test
    void findByUser_WhenPreferencesExist_ShouldReturnPreferences() {
        // Given
        entityManager.persistAndFlush(testPreferences);

        // When
        Optional<UserPreferences> result = userPreferencesRepository.findByUser(testUser);

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getUser().getId()).isEqualTo(testUser.getId());
        assertThat(result.get().getEmailNotifications()).isTrue();
        assertThat(result.get().getLanguage()).isEqualTo("en");
    }

    @Test
    void findByUser_WhenPreferencesDoNotExist_ShouldReturnEmpty() {
        // Given
        User anotherUser = User.builder()
                .username("anotheruser")
                .password("password")
                .email("another@example.com")
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();
        anotherUser = entityManager.persistAndFlush(anotherUser);

        // When
        Optional<UserPreferences> result = userPreferencesRepository.findByUser(anotherUser);

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    @Transactional
    void deleteByUser_WhenPreferencesExist_ShouldDeleteUserPreferences() {
        // Given
        entityManager.persistAndFlush(testPreferences);

        // Create another user with preferences to ensure we only delete current user's
        // preferences
        User anotherUser = User.builder()
                .username("anotheruser")
                .password("password")
                .email("another@example.com")
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();
        anotherUser = entityManager.persistAndFlush(anotherUser);

        UserPreferences anotherPreferences = UserPreferences.builder()
                .user(anotherUser)
                .emailNotifications(false)
                .language("fr")
                .build();
        entityManager.persistAndFlush(anotherPreferences);

        // When
        userPreferencesRepository.deleteByUser(testUser);
        entityManager.flush();

        // Then
        Optional<UserPreferences> deletedPreferences = userPreferencesRepository.findByUser(testUser);
        Optional<UserPreferences> remainingPreferences = userPreferencesRepository.findByUser(anotherUser);

        assertThat(deletedPreferences).isEmpty();
        assertThat(remainingPreferences).isPresent();
    }

    @Test
    void update_WhenPreferencesExist_ShouldUpdateSuccessfully() {
        // Given
        UserPreferences savedPreferences = entityManager.persistAndFlush(testPreferences);
        entityManager.detach(savedPreferences);

        // When
        savedPreferences.setEmailNotifications(false);
        savedPreferences.setSmsNotifications(true);
        savedPreferences.setLanguage("es");
        savedPreferences.setMarketingEmails(true);
        UserPreferences updatedPreferences = userPreferencesRepository.save(savedPreferences);

        // Then
        assertThat(updatedPreferences.getEmailNotifications()).isFalse();
        assertThat(updatedPreferences.getSmsNotifications()).isTrue();
        assertThat(updatedPreferences.getLanguage()).isEqualTo("es");
        assertThat(updatedPreferences.getMarketingEmails()).isTrue();
        assertThat(updatedPreferences.getUser().getId()).isEqualTo(testUser.getId()); // Should remain unchanged
    }

    @Test
    void findById_WhenPreferencesExist_ShouldReturnPreferences() {
        // Given
        UserPreferences savedPreferences = entityManager.persistAndFlush(testPreferences);

        // When
        Optional<UserPreferences> result = userPreferencesRepository.findById(savedPreferences.getId());

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(savedPreferences.getId());
        assertThat(result.get().getUser().getId()).isEqualTo(testUser.getId());
    }

    @Test
    void findById_WhenPreferencesDoNotExist_ShouldReturnEmpty() {
        // When
        Optional<UserPreferences> result = userPreferencesRepository.findById("non-existent-id");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    void findAll_ShouldReturnAllPreferences() {
        // Given
        User user1 = User.builder()
                .username("user1")
                .password("password")
                .email("user1@example.com")
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();
        user1 = entityManager.persistAndFlush(user1);

        User user2 = User.builder()
                .username("user2")
                .password("password")
                .email("user2@example.com")
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();
        user2 = entityManager.persistAndFlush(user2);

        UserPreferences prefs1 = UserPreferences.builder()
                .user(user1)
                .language("en")
                .emailNotifications(true)
                .build();

        UserPreferences prefs2 = UserPreferences.builder()
                .user(user2)
                .language("fr")
                .emailNotifications(false)
                .build();

        entityManager.persistAndFlush(prefs1);
        entityManager.persistAndFlush(prefs2);

        // When
        List<UserPreferences> allPreferences = userPreferencesRepository.findAll();

        // Then
        assertThat(allPreferences).hasSize(2);
        assertThat(allPreferences).extracting("language")
                .containsExactlyInAnyOrder("en", "fr");
    }

    @Test
    void count_ShouldReturnCorrectCount() {
        // Given
        entityManager.persistAndFlush(testPreferences);

        User anotherUser = User.builder()
                .username("user2")
                .password("password")
                .email("user2@example.com")
                .enabled(true)
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .build();
        anotherUser = entityManager.persistAndFlush(anotherUser);

        UserPreferences secondPreferences = UserPreferences.builder()
                .user(anotherUser)
                .language("fr")
                .build();
        entityManager.persistAndFlush(secondPreferences);

        // When
        long count = userPreferencesRepository.count();

        // Then
        assertThat(count).isEqualTo(2);
    }

    @Test
    void save_WithDifferentLanguages_ShouldPersistSuccessfully() {
        // Given
        String[] languages = { "en", "es", "fr", "de", "it", "pt", "ja", "zh", "ko", "ar" };

        for (int i = 0; i < languages.length; i++) {
            User user = User.builder()
                    .username("user" + i)
                    .password("password")
                    .email("user" + i + "@example.com")
                    .enabled(true)
                    .emailVerified(false)
                    .createdAt(LocalDateTime.now())
                    .build();
            user = entityManager.persistAndFlush(user);

            UserPreferences preferences = UserPreferences.builder()
                    .user(user)
                    .language(languages[i])
                    .build();

            // When
            UserPreferences savedPreferences = userPreferencesRepository.save(preferences);

            // Then
            assertThat(savedPreferences.getId()).isNotNull();
            assertThat(savedPreferences.getLanguage()).isEqualTo(languages[i]);
            assertThat(savedPreferences.getUser().getId()).isEqualTo(user.getId());
        }
    }

    @Test
    void save_WithAllNotificationsDisabled_ShouldPersistSuccessfully() {
        // Given
        UserPreferences allDisabledPreferences = UserPreferences.builder()
                .user(testUser)
                .emailNotifications(false)
                .smsNotifications(false)
                .pushNotifications(false)
                .appointmentReminders(false)
                .serviceUpdates(false)
                .marketingEmails(false)
                .language("en")
                .build();

        // When
        UserPreferences savedPreferences = userPreferencesRepository.save(allDisabledPreferences);

        // Then
        assertThat(savedPreferences.getId()).isNotNull();
        assertThat(savedPreferences.getEmailNotifications()).isFalse();
        assertThat(savedPreferences.getSmsNotifications()).isFalse();
        assertThat(savedPreferences.getPushNotifications()).isFalse();
        assertThat(savedPreferences.getAppointmentReminders()).isFalse();
        assertThat(savedPreferences.getServiceUpdates()).isFalse();
        assertThat(savedPreferences.getMarketingEmails()).isFalse();
    }

    @Test
    void existsById_WhenPreferencesExist_ShouldReturnTrue() {
        // Given
        UserPreferences savedPreferences = entityManager.persistAndFlush(testPreferences);

        // When
        boolean exists = userPreferencesRepository.existsById(savedPreferences.getId());

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void existsById_WhenPreferencesDoNotExist_ShouldReturnFalse() {
        // When
        boolean exists = userPreferencesRepository.existsById("non-existent-id");

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    void deleteById_WhenPreferencesExist_ShouldRemovePreferences() {
        // Given
        UserPreferences savedPreferences = entityManager.persistAndFlush(testPreferences);
        String preferencesId = savedPreferences.getId();

        // When
        userPreferencesRepository.deleteById(preferencesId);
        entityManager.flush();

        // Then
        Optional<UserPreferences> result = userPreferencesRepository.findById(preferencesId);
        assertThat(result).isEmpty();
    }
}