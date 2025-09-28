package com.techtorque.auth_service.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * A controller to handle the default favicon.ico request by redirecting
 * it to the favicon provided by the Swagger UI resources.
 */
@Controller
public class FaviconController {

  @GetMapping("favicon.ico")
  @ResponseBody
  public String faviconRedirect() {
    // Redirect to the favicon included with the springdoc-openapi-ui library
    return "redirect:/swagger-ui/favicon-32x32.png";
  }
}