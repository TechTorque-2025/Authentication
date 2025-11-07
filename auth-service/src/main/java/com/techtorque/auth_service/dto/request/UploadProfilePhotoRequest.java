package com.techtorque.auth_service.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for uploading profile photos
 * Accepts base64 encoded image data from the frontend
 * Includes size and MIME type validation
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UploadProfilePhotoRequest {

    private String base64Image;
    private String mimeType;

    // Size constants (in bytes)
    private static final long MIN_SIZE = 1024;  // 1KB
    private static final long MAX_SIZE = 5_242_880;  // 5MB

    // Allowed MIME types
    private static final String[] ALLOWED_TYPES = {
            "image/jpeg", "image/jpg", "image/png", "image/gif",
            "image/webp", "image/bmp", "image/tiff"
    };

    /**
     * Validates the photo request
     * Checks for non-empty base64 and valid MIME type
     */
    public boolean isValid() {
        return base64Image != null && !base64Image.isEmpty() &&
               mimeType != null && isAllowedMimeType(mimeType);
    }

    /**
     * Validate MIME type is allowed
     */
    private static boolean isAllowedMimeType(String mimeType) {
        if (mimeType == null || mimeType.isEmpty()) {
            return false;
        }

        for (String allowed : ALLOWED_TYPES) {
            if (allowed.equalsIgnoreCase(mimeType)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get error message for invalid MIME type
     */
    public String getInvalidMimeTypeError() {
        return "Invalid MIME type: " + mimeType + ". Allowed types: JPEG, PNG, GIF, WebP, BMP, TIFF";
    }
}
