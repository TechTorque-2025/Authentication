package com.techtorque.auth_service.service;

import com.techtorque.auth_service.entity.User;
import com.techtorque.auth_service.repository.UserRepository;
import com.techtorque.auth_service.dto.response.ProfilePhotoDto;
import com.techtorque.auth_service.dto.response.ProfilePhotoCacheEntry;
import com.techtorque.auth_service.dto.request.UploadProfilePhotoRequest;
import com.google.common.cache.Cache;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Optional;

/**
 * Service for managing user profile photos with BLOB storage and caching
 * - Stores images as binary data (BLOB) in the database
 * - Implements in-memory cache for frequently accessed photos
 * - Only updates cache when photo is actually changed
 * - Supports cache invalidation on photo updates
 * - Enforces image size limits and validation
 */
@Service
@Transactional
public class ProfilePhotoService {

    // Image size limits (in bytes)
    public static final long MIN_IMAGE_SIZE = 1024;  // 1KB minimum
    public static final long MAX_IMAGE_SIZE = 5_242_880;  // 5MB maximum
    public static final long MEDIUM_IMAGE_SIZE = 2_097_152;  // 2MB medium warning threshold

    // Allowed MIME types
    public static final String[] ALLOWED_MIME_TYPES = {
            "image/jpeg",
            "image/jpg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/bmp",
            "image/tiff"
    };

    private final UserRepository userRepository;

    @Autowired
    private Cache<Long, byte[]> profilePhotoCache;

    @Autowired
    private Cache<Long, ProfilePhotoCacheEntry> profilePhotoMetadataCache;

    public ProfilePhotoService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Upload a profile photo for a user
     * - Converts base64 to binary data
     * - Validates file size and MIME type
     * - Stores in database as BLOB
     * - Invalidates cache so next read gets fresh data
     *
     * @param userId The user ID
     * @param request Upload request with base64 image and MIME type
     * @return Updated ProfilePhotoDto
     * @throws IllegalArgumentException if validation fails
     */
    public ProfilePhotoDto uploadProfilePhoto(Long userId, UploadProfilePhotoRequest request) {
        if (!request.isValid()) {
            throw new IllegalArgumentException("Invalid image data or MIME type");
        }

        // Validate MIME type
        if (!isAllowedMimeType(request.getMimeType())) {
            throw new IllegalArgumentException(
                    "MIME type not allowed. Supported types: JPEG, PNG, GIF, WebP, BMP, TIFF"
            );
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));

        // Decode base64 to binary
        byte[] photoData;
        try {
            String base64Image = request.getBase64Image();

            // Clean up base64 string - remove whitespace and line breaks
            base64Image = base64Image.replaceAll("\\s+", "");

            // Additional validation - base64 should only contain valid characters
            if (!base64Image.matches("^[A-Za-z0-9+/]*={0,2}$")) {
                throw new IllegalArgumentException("Base64 string contains invalid characters");
            }

            photoData = Base64.getDecoder().decode(base64Image);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid base64 encoding: " + e.getMessage());
        }

        // Validate file size
        validateImageSize(photoData.length);

        // Update user entity
        user.setProfilePhoto(photoData);
        user.setProfilePhotoMimeType(request.getMimeType());
        user.setProfilePhotoUpdatedAt(LocalDateTime.now());

        // Save to database
        User savedUser = userRepository.save(user);

        // Invalidate cache entries for this user
        invalidatePhotoCache(userId);

        return ProfilePhotoDto.fromBinary(
                userId,
                photoData,
                request.getMimeType(),
                convertToMillis(savedUser.getProfilePhotoUpdatedAt())
        );
    }

    /**
     * Get profile photo for a user with cache support
     * - First checks in-memory cache
     * - If not in cache, loads from database
     * - Stores in cache for future requests
     * - Returns null if no photo exists
     *
     * @param userId The user ID
     * @return ProfilePhotoDto with base64 encoded image, or null if not found
     */
    public ProfilePhotoDto getProfilePhoto(Long userId) {
        // Try to get from cache first
        byte[] cachedPhoto = profilePhotoCache.getIfPresent(userId);

        if (cachedPhoto != null) {
            ProfilePhotoCacheEntry metadata = profilePhotoMetadataCache.getIfPresent(userId);
            if (metadata != null) {
                return ProfilePhotoDto.builder()
                        .userId(userId)
                        .base64Image(Base64.getEncoder().encodeToString(cachedPhoto))
                        .mimeType(metadata.mimeType)
                        .fileSize((long) cachedPhoto.length)
                        .lastUpdated(metadata.timestamp)
                        .build();
            }
        }

        // Load from database if not in cache
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));

        if (user.getProfilePhoto() == null || user.getProfilePhoto().length == 0) {
            return null;
        }

        // Cache the photo for future requests
        profilePhotoCache.put(userId, user.getProfilePhoto());
        profilePhotoMetadataCache.put(userId, new ProfilePhotoCacheEntry(
                convertToMillis(user.getProfilePhotoUpdatedAt()),
                user.getProfilePhotoMimeType(),
                (long) user.getProfilePhoto().length
        ));

        return ProfilePhotoDto.fromBinary(
                userId,
                user.getProfilePhoto(),
                user.getProfilePhotoMimeType(),
                convertToMillis(user.getProfilePhotoUpdatedAt())
        );
    }

    /**
     * Get raw binary photo data for streaming/download
     * Useful for serving images directly without base64 encoding
     *
     * @param userId The user ID
     * @return Byte array of photo data, or empty array if not found
     */
    public byte[] getProfilePhotoBinary(Long userId) {
        // Try cache first
        byte[] cachedPhoto = profilePhotoCache.getIfPresent(userId);
        if (cachedPhoto != null) {
            return cachedPhoto;
        }

        // Load from database
        return userRepository.findById(userId)
                .map(user -> {
                    if (user.getProfilePhoto() != null && user.getProfilePhoto().length > 0) {
                        // Cache it for future requests
                        profilePhotoCache.put(userId, user.getProfilePhoto());
                        return user.getProfilePhoto();
                    }
                    return new byte[0];
                })
                .orElse(new byte[0]);
    }

    /**
     * Delete the profile photo for a user
     * - Removes from database
     * - Invalidates cache
     *
     * @param userId The user ID
     */
    public void deleteProfilePhoto(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));

        user.setProfilePhoto(null);
        user.setProfilePhotoMimeType(null);
        user.setProfilePhotoUpdatedAt(null);

        userRepository.save(user);

        // Invalidate cache
        invalidatePhotoCache(userId);
    }

    /**
     * Check if a profile photo exists and get metadata
     * Useful for conditional rendering and cache validation
     *
     * @param userId The user ID
     * @return CacheEntry with metadata if photo exists, null otherwise
     */
    public ProfilePhotoCacheEntry getPhotoMetadata(Long userId) {
        // Check cache first
        ProfilePhotoCacheEntry cached = profilePhotoMetadataCache.getIfPresent(userId);
        if (cached != null) {
            return cached;
        }

        // Load from database
        return userRepository.findById(userId)
                .map(user -> {
                    if (user.getProfilePhoto() != null && user.getProfilePhoto().length > 0) {
                        ProfilePhotoCacheEntry entry = new ProfilePhotoCacheEntry(
                                convertToMillis(user.getProfilePhotoUpdatedAt()),
                                user.getProfilePhotoMimeType(),
                                (long) user.getProfilePhoto().length
                        );
                        // Cache for future requests
                        profilePhotoMetadataCache.put(userId, entry);
                        return entry;
                    }
                    return null;
                })
                .orElse(null);
    }

    /**
     * Invalidate cache entries for a user
     * Called when profile photo is updated or deleted
     *
     * @param userId The user ID
     */
    private void invalidatePhotoCache(Long userId) {
        profilePhotoCache.invalidate(userId);
        profilePhotoMetadataCache.invalidate(userId);
    }

    /**
     * Clear all cache entries
     * Can be called during maintenance or cache reset
     */
    public void clearAllCache() {
        profilePhotoCache.invalidateAll();
        profilePhotoMetadataCache.invalidateAll();
    }

    /**
     * Validate image file size
     * Enforces minimum and maximum size limits
     *
     * @param fileSize The file size in bytes
     * @throws IllegalArgumentException if size is outside acceptable range
     */
    private void validateImageSize(long fileSize) {
        if (fileSize < MIN_IMAGE_SIZE) {
            throw new IllegalArgumentException(
                    String.format("Image is too small. Minimum size: %dKB", MIN_IMAGE_SIZE / 1024)
            );
        }

        if (fileSize > MAX_IMAGE_SIZE) {
            throw new IllegalArgumentException(
                    String.format("Image size exceeds maximum limit of %dMB", MAX_IMAGE_SIZE / 1_048_576)
            );
        }

        // Warning for medium-sized images (log if needed)
        if (fileSize > MEDIUM_IMAGE_SIZE) {
            // Could add logging here if needed
            // logger.warn("Large image uploaded: {}MB", fileSize / 1_048_576);
        }
    }

    /**
     * Check if MIME type is allowed
     * Prevents upload of non-image files
     *
     * @param mimeType The MIME type to validate
     * @return true if MIME type is allowed, false otherwise
     */
    private boolean isAllowedMimeType(String mimeType) {
        if (mimeType == null || mimeType.isEmpty()) {
            return false;
        }

        for (String allowed : ALLOWED_MIME_TYPES) {
            if (allowed.equalsIgnoreCase(mimeType)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get human-readable file size string
     * Useful for error messages and logging
     *
     * @param bytes The size in bytes
     * @return Formatted size string (e.g., "2.5MB")
     */
    public static String formatFileSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1_048_576) return String.format("%.2f KB", bytes / 1024.0);
        if (bytes < 1_073_741_824) return String.format("%.2f MB", bytes / 1_048_576.0);
        return String.format("%.2f GB", bytes / 1_073_741_824.0);
    }

    /**
     * Convert LocalDateTime to milliseconds since epoch
     * Used for cache validation timestamps
     *
     * @param localDateTime The LocalDateTime to convert
     * @return Milliseconds since epoch (Jan 1, 1970)
     */
    private static long convertToMillis(LocalDateTime localDateTime) {
        if (localDateTime == null) {
            return System.currentTimeMillis();
        }
        return localDateTime.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }
}
