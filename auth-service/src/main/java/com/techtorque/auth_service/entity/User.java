package com.techtorque.auth_service.entity;

import jakarta.persistence.*;
import lombok.*; // Import EqualsAndHashCode, Getter, Setter, ToString

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
@ToString(exclude = "roles") // Exclude the collection to prevent infinite loops
@EqualsAndHashCode(exclude = "roles") // Exclude the collection from equals/hashCode
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

  @Column(nullable = false)
  @Builder.Default
  private Boolean enabled = true;

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
  }

  public void addRole(Role role) {
    this.roles.add(role);
  }
}