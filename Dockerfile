# Dockerfile for auth-service

# --- Build Stage ---
# Use the official Maven image which contains the Java JDK
FROM maven:3.8-eclipse-temurin-17 AS build

# Set the working directory
WORKDIR /app

# Copy the pom.xml and download dependencies
COPY auth-service/pom.xml .
RUN mvn -B dependency:go-offline

# Copy the rest of the source code and build the application
# Note: We copy the pom.xml *first* to leverage Docker layer caching.
COPY auth-service/src ./src
RUN mvn -B clean package -DskipTests

# --- Run Stage ---
# Use a minimal JRE image for the final container
FROM eclipse-temurin:17-jre-jammy

# Set a working directory
WORKDIR /app

# Copy the built JAR from the 'build' stage
# The wildcard is used in case the version number is in the JAR name
COPY --from=build /app/target/*.jar app.jar

# Expose the port your application runs on (e.g., 8080)
EXPOSE 8080

# The command to run your application
ENTRYPOINT ["java", "-jar", "app.jar"]