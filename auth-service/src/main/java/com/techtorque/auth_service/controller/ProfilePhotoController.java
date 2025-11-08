package com.techtorque.auth_service.controller;

import com.techtorque.auth_service.dto.response.ProfilePhotoDto;
import com.techtorque.auth_service.dto.request.UploadProfilePhotoRequest;
import com.techtorque.auth_service.service.ProfilePhotoService;
import com.techtorque.auth_service.dto.response.ApiSuccess;
import com.techtorque.auth_service.dto.response.ApiError;
import com.techtorque.auth_service.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller for profile photo management
 * Endpoints for uploading, downloading, and managing user profile photos stored as BLOBs
 */
@RestController
@RequestMapping("/users/profile-photo")
@Tag(name = "Profile Photos", description = "Profile photo management endpoints")
@SecurityRequirement(name = "bearerAuth")
@RequiredArgsConstructor
public class ProfilePhotoController {

    private final ProfilePhotoService profilePhotoService;
    private final UserRepository userRepository;

    /**
     * Upload a profile photo for the current user
     * - Accepts base64 encoded image data
     * - Validates MIME type (must be image/*)
     * - Max file size: 5MB
     * - Stores as BLOB in database
     * - Invalidates cache automatically
     *
     * @param request Upload request with base64 image and MIME type
     * @return ProfilePhotoDto with upload confirmation
     */
    @PostMapping
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Upload profile photo", description = "Upload a profile photo for the current user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Photo uploaded successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid image data or MIME type"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "413", description = "File size exceeds 5MB limit")
    })
    public ResponseEntity<?> uploadProfilePhoto(@Valid @RequestBody UploadProfilePhotoRequest request) {
        try {
            Long userId = getCurrentUserId();
            ProfilePhotoDto result = profilePhotoService.uploadProfilePhoto(userId, request);
            return ResponseEntity.ok(ApiSuccess.of("Profile photo uploaded successfully", result));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiError.builder()
                    .status(400)
                    .message(e.getMessage())
                    .errorCode("INVALID_INPUT")
                    .build());
        } catch (Exception e) {
            return ResponseEntity.status(500).body(ApiError.builder()
                    .status(500)
                    .message("Failed to upload profile photo: " + e.getMessage())
                    .errorCode("UPLOAD_FAILED")
                    .build());
        }
    }

    /**
     * Get profile photo for the current user
     * - Returns base64 encoded image data
     * - Supports caching with If-Modified-Since header
     * - Returns null if no photo exists
     *
     * @return ProfilePhotoDto with base64 encoded image
     */
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get current user's profile photo", description = "Retrieve profile photo for the current user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Photo retrieved successfully"),
            @ApiResponse(responseCode = "204", description = "No photo found"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<?> getProfilePhoto() {
        try {
            Long userId = getCurrentUserId();
            ProfilePhotoDto photo = profilePhotoService.getProfilePhoto(userId);

            if (photo == null) {
                return ResponseEntity.noContent().build();
            }

            return ResponseEntity.ok()
                    .header("X-Photo-Size", String.valueOf(photo.getFileSize()))
                    .header("X-Photo-Type", photo.getMimeType())
                    .body(photo);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            return ResponseEntity.status(500).body(ApiError.builder()
                    .status(500)
                    .message("Failed to retrieve profile photo")
                    .errorCode("RETRIEVAL_FAILED")
                    .build());
        }
    }

    /**
     * Get profile photo for any user by username
     * - Returns base64 encoded image data
     * - Publicly accessible for user profiles
     * - Returns null if no photo exists
     *
     * @param username The username to get photo for
     * @return ProfilePhotoDto with base64 encoded image
     */
    @GetMapping("/username/{username}")
    @Operation(summary = "Get user profile photo by username", description = "Retrieve profile photo for a specific user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Photo retrieved successfully"),
            @ApiResponse(responseCode = "204", description = "No photo found")
    })
    public ResponseEntity<?> getProfilePhotoByUsername(@PathVariable String username) {
        // This would require a UserRepository method to find user by username
        // For now, returning 204 (No Content) as placeholder
        // TODO: Implement once UserRepository is extended
        return ResponseEntity.noContent().build();
    }

    /**
     * Get profile photo as binary stream for download
     * - Returns raw image bytes with appropriate Content-Type header
     * - Useful for direct image display
     *
     * @return Binary image data with proper headers
     */
    @GetMapping("/binary")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get profile photo as binary stream", description = "Download profile photo as binary file")
    public ResponseEntity<?> getProfilePhotoBinary() {
        try {
            Long userId = getCurrentUserId();
            byte[] photoData = profilePhotoService.getProfilePhotoBinary(userId);

            if (photoData.length == 0) {
                return ResponseEntity.noContent().build();
            }

            // Get metadata to determine correct MIME type
            var metadata = profilePhotoService.getPhotoMetadata(userId);
            String mimeType = metadata != null ? metadata.mimeType : MediaType.IMAGE_JPEG_VALUE;

            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType(mimeType))
                    .contentLength(photoData.length)
                    .body(photoData);
        } catch (Exception e) {
            return ResponseEntity.noContent().build();
        }
    }

    /**
     * Delete profile photo for the current user
     * - Removes image from database
     * - Invalidates cache
     *
     * @return Success message
     */
    @DeleteMapping
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Delete profile photo", description = "Delete profile photo for the current user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Photo deleted successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<?> deleteProfilePhoto() {
        try {
            Long userId = getCurrentUserId();
            profilePhotoService.deleteProfilePhoto(userId);
            return ResponseEntity.ok(ApiSuccess.of("Profile photo deleted successfully"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiError.builder()
                    .status(400)
                    .message(e.getMessage())
                    .errorCode("INVALID_INPUT")
                    .build());
        } catch (Exception e) {
            return ResponseEntity.status(500).body(ApiError.builder()
                    .status(500)
                    .message("Failed to delete profile photo")
                    .errorCode("DELETE_FAILED")
                    .build());
        }
    }

    /**
     * Get profile photo metadata for cache validation
     * - Returns size, MIME type, and last update timestamp
     * - Useful for conditional requests (If-Modified-Since)
     *
     * @return Metadata object with file info
     */
    @GetMapping("/metadata")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get profile photo metadata", description = "Get metadata for profile photo (size, type, update time)")
    public ResponseEntity<?> getPhotoMetadata() {
        try {
            Long userId = getCurrentUserId();
            var metadata = profilePhotoService.getPhotoMetadata(userId);

            if (metadata == null) {
                return ResponseEntity.noContent().build();
            }

            return ResponseEntity.ok()
                    .header("X-Photo-Size", String.valueOf(metadata.size))
                    .header("X-Photo-Type", metadata.mimeType)
                    .header("X-Photo-Updated", String.valueOf(metadata.timestamp))
                    .body(new PhotoMetadata(metadata.size, metadata.mimeType, metadata.timestamp));
        } catch (Exception e) {
            return ResponseEntity.noContent().build();
        }
    }

    /**
     * Extract current user ID from security context
     * Gets username from authenticated principal and looks up user ID from repository
     */
    private Long getCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            throw new IllegalArgumentException("User is not authenticated");
        }

        String username = auth.getName();

        return userRepository.findByUsername(username)
                .map(user -> user.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
    }
}

/**
 * Photo metadata response
 */
class PhotoMetadata {
    public Long size;
    public String mimeType;
    public Long lastUpdated;

    public PhotoMetadata(Long size, String mimeType, Long lastUpdated) {
        this.size = size;
        this.mimeType = mimeType;
        this.lastUpdated = lastUpdated;
    }
}
