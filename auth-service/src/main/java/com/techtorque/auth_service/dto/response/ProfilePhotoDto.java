package com.techtorque.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for profile photo response
 * Contains base64 encoded image data for UI display
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ProfilePhotoDto {

    private Long userId;
    private String base64Image;
    private String mimeType;
    private Long fileSize;
    private Long lastUpdated;

    /**
     * Factory method to convert binary photo data to DTO
     */
    public static ProfilePhotoDto fromBinary(Long userId, byte[] photoData, String mimeType, Long lastUpdated) {
        if (photoData == null || photoData.length == 0) {
            return null;
        }

        String base64 = java.util.Base64.getEncoder().encodeToString(photoData);
        return ProfilePhotoDto.builder()
                .userId(userId)
                .base64Image(base64)
                .mimeType(mimeType != null ? mimeType : "image/jpeg")
                .fileSize((long) photoData.length)
                .lastUpdated(lastUpdated)
                .build();
    }
}

