package test.weewee.userservice.dto;

import lombok.Data;

@Data
public class TokenResponse {
    private String accessToken;
    private UserResponse user;
}