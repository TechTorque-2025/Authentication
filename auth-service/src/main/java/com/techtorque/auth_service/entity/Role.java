package com.techtorque.auth_service.entity;

import jakarta.persistence.*;
import lombok.*; // Import EqualsAndHashCode, Getter, Setter, ToString

import java.util.Set;

/**
 * Role entity representing user roles in the system
 * Each role contains multiple permissions that define what actions can be performed
 */
@Entity
@Table(name = "roles")
// --- Start of Changes ---
@Getter
@Setter
@ToString(exclude = {"users", "permissions"}) // Exclude collections to prevent infinite loops
@EqualsAndHashCode(exclude = {"users", "permissions"}) // Exclude collections from equals/hashCode
// --- End of Changes ---
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(unique = true, nullable = false)
  @Enumerated(EnumType.STRING)
  private RoleName name;

  private String description;

  // This is the lazy collection causing the LazyInitializationException
  @ManyToMany(mappedBy = "roles")
  private Set<User> users;

  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(
          name = "role_permissions",
          joinColumns = @JoinColumn(name = "role_id"),
          inverseJoinColumns = @JoinColumn(name = "permission_id")
  )
  private Set<Permission> permissions;
}