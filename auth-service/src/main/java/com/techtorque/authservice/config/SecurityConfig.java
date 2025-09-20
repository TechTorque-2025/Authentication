package com.techtorque.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            // Disable CSRF since we are using JWTs (stateless)
            .csrf(csrf -> csrf.disable())
            // We want stateless sessions; the server doesn't hold session state.
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Define authorization rules
            .authorizeHttpRequests(auth -> auth
                    // Allow anyone to access the /login endpoint
                    .requestMatchers("/login").permitAll()
                    // Any other request must be authenticated (though we have no other endpoints)
                    .anyRequest().authenticated()
            );
    return http.build();
  }
}