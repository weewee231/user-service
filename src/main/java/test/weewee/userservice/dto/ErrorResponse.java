package test.weewee.userservice.dto;

import lombok.Data;
import java.util.Map;

@Data
public class ErrorResponse {
    private Map<String, String> errors;

    public ErrorResponse(Map<String, String> errors) {
        this.errors = errors;
    }

    public static ErrorResponse of(Map<String, String> errors) {
        return new ErrorResponse(errors);
    }

    public static ErrorResponse of(String key, String value) {
        return new ErrorResponse(Map.of(key, value));
    }
}