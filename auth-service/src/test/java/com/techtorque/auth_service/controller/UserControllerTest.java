package com.techtorque.auth_service.controller;

import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
class UserControllerTest {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private UserService userService;

  @MockBean
  private com.techtorque.auth_service.service.PreferencesService preferencesService;

  @Test
  @WithMockUser(username = "testuser", roles = {"CUSTOMER"})
  void getCurrentUserProfile_whenAuthenticatedCustomer_shouldReturnProfile() throws Exception {
    User user = new User();
    user.setUsername("testuser");
    user.setFullName("Test User");

    when(userService.findByUsername(anyString())).thenReturn(Optional.of(user));

    mockMvc.perform(get("/users/me"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("testuser"))
            .andExpect(jsonPath("$.fullName").value("Test User"));
  }
}
