package com.techtorque.auth_service.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.lang.NonNull;

import java.sql.Connection;
import java.sql.DriverManager;

public class DatabasePreflightInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

  private static final Logger logger = LoggerFactory.getLogger(DatabasePreflightInitializer.class);

  @Override
  public void initialize(@NonNull ConfigurableApplicationContext applicationContext) {
    ConfigurableEnvironment env = applicationContext.getEnvironment();

    String jdbcUrl = env.getProperty("spring.datasource.url");
    String username = env.getProperty("spring.datasource.username");
    String password = env.getProperty("spring.datasource.password");

    if (jdbcUrl == null) {
      logger.warn("Database URL not configured, skipping preflight connection check.");
      return;
    }

    logger.info("Performing database preflight check...");

    try (Connection connection = DriverManager.getConnection(jdbcUrl, username, password)) {
      logger.info("Database preflight check successful!");
    } catch (Exception e) {
      logger.error("\n\n************************************************************");
      logger.error("** DATABASE PREFLIGHT CHECK FAILED!                       **");
      logger.error("** Could not connect to the database at URL: {}", jdbcUrl);
      logger.error("** Please ensure it is running and accessible.            **");
      logger.error("************************************************************\n");

      System.exit(1);
    }
  }
}
