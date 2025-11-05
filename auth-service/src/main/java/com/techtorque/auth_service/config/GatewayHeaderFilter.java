package com.techtorque.auth_service.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Filter to extract user authentication from Gateway headers.
 * The API Gateway injects X-User-Subject and X-User-Roles headers
 * after validating the JWT token. This filter uses those headers
 * to establish the Spring Security authentication context.
 */
@Slf4j
public class GatewayHeaderFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
          throws ServletException, IOException {

    String userId = request.getHeader("X-User-Subject");
    String rolesHeader = request.getHeader("X-User-Roles");

    log.debug("Processing request - Path: {}, User-Subject: {}, User-Roles: {}",
              request.getRequestURI(), userId, rolesHeader);

    if (userId != null && !userId.isEmpty()) {
      List<SimpleGrantedAuthority> authorities = rolesHeader == null ? Collections.emptyList() :
              Arrays.stream(rolesHeader.split(","))
                      .map(role -> new SimpleGrantedAuthority("ROLE_" + role.trim().toUpperCase()))
                      .collect(Collectors.toList());

      log.debug("Authenticated user: {} with authorities: {}", userId, authorities);

      UsernamePasswordAuthenticationToken authentication =
              new UsernamePasswordAuthenticationToken(userId, null, authorities);

      SecurityContextHolder.getContext().setAuthentication(authentication);
    } else {
      log.debug("No X-User-Subject header found in request to {}", request.getRequestURI());
    }

    filterChain.doFilter(request, response);
  }
}
