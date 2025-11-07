package com.techtorque.auth_service.entity;

import jakarta.persistence.*;
import lombok.*; // Import EqualsAndHashCode, Getter, Setter, ToString
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * User entity representing users in the authentication system
 * Contains user credentials and role assignments
 */
@Entity
@Table(name = "users")
// --- Start of Changes ---
@Getter
@Setter
@ToString(exclude = {"roles", "profilePhoto"}) // Exclude collections and BLOB to prevent infinite loops
@EqualsAndHashCode(exclude = {"roles", "profilePhoto"}) // Exclude from equals/hashCode
// --- End of Changes ---
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(unique = true, nullable = false)
  private String username;

  @Column(nullable = false)
  private String password;

  @Column(unique = true, nullable = false)
  private String email;

  @Column
  private String fullName;

  @Column
  private String phone;

  @Column(length = 500)
  private String address;

  @Column
  private String profilePhotoUrl;

  // Binary profile photo data (BLOB) - stores the actual image bytes
  @Lob
  @Column(columnDefinition = "BYTEA")
  @JdbcTypeCode(SqlTypes.VARBINARY)
  private byte[] profilePhoto;

  // Timestamp for cache validation - updated only when profile photo changes
  @Column(name = "profile_photo_updated_at")
  private LocalDateTime profilePhotoUpdatedAt;

  // MIME type of the profile photo (e.g., "image/jpeg", "image/png")
  @Column(name = "profile_photo_mime_type", length = 50)
  private String profilePhotoMimeType;

  @Column(nullable = false)
  @Builder.Default
  private Boolean enabled = true;

  @Column(nullable = false)
  @Builder.Default
  private Boolean emailVerified = false;

  @Column(name = "email_verification_deadline")
  private LocalDateTime emailVerificationDeadline;

  @Column(name = "created_at")
  @Builder.Default
  private LocalDateTime createdAt = LocalDateTime.now();

  // This is the other side of the relationship
  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(
          name = "user_roles",
          joinColumns = @JoinColumn(name = "user_id"),
          inverseJoinColumns = @JoinColumn(name = "role_id")
  )
  @Builder.Default
  private Set<Role> roles = new HashSet<>();

  public User(String username, String password, String email) {
    this.username = username;
    this.password = password;
    this.email = email;
    this.enabled = true;
    this.createdAt = LocalDateTime.now();
    this.roles = new HashSet<>();
    this.emailVerified = false;
  }

  public void addRole(Role role) {
    this.roles.add(role);
  }
}