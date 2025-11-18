package test.weewee.userservice.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import test.weewee.userservice.security.JwtUtil;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final JwtUtil jwtUtil;

    public void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        log.debug("Setting refresh token cookie");
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
        response.addCookie(cookie);
    }

    public void clearRefreshTokenCookie(HttpServletResponse response) {
        log.debug("Clearing refresh token cookie");
        Cookie cookie = new Cookie("refreshToken", "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    public Optional<String> getRefreshTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() == null) {
            log.debug("No cookies in request");
            return Optional.empty();
        }

        Optional<String> refreshToken = Arrays.stream(request.getCookies())
                .filter(cookie -> "refreshToken".equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst();

        log.debug("Refresh token from cookies: {}", refreshToken.isPresent() ? "found" : "not found");
        return refreshToken;
    }

    public Optional<String> getUserEmailFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (jwtUtil.validateToken(token)) {
                String userEmail = jwtUtil.getEmailFromToken(token);
                log.debug("User email from token: {}", userEmail);
                return Optional.of(userEmail);
            }
        }
        log.debug("No valid authorization header found");
        return Optional.empty();
    }

    public void invalidateUserTokens(HttpServletResponse response) {
        log.debug("Invalidating all user tokens");
        clearRefreshTokenCookie(response);

    }
}