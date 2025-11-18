package test.weewee.userservice.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import test.weewee.userservice.model.User;
import test.weewee.userservice.repository.UserRepository;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthService authService; // ← ДОБАВЛЯЕМ

    public User createUser(User user) {
        log.debug("Creating new user: {}", user.getEmail());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        User savedUser = userRepository.save(user);
        log.info("User created with ID: {}", savedUser.getId());
        return savedUser;
    }

    public Optional<User> findByEmail(String email) {
        log.debug("Finding user by email: {}", email);
        return userRepository.findByEmail(email);
    }

    public Optional<User> findById(UUID id) {
        log.debug("Finding user by ID: {}", id);
        return userRepository.findById(id);
    }

    public boolean existsByEmail(String email) {
        log.debug("Checking if email exists: {}", email);
        return userRepository.existsByEmail(email);
    }

    public User updateUser(UUID id, User updatedUser) {
        log.debug("Updating user with ID: {}", id);

        return userRepository.findById(id).map(user -> {
            if (updatedUser.getEmail() != null) {
                log.debug("Updating email for user {}", id);
                user.setEmail(updatedUser.getEmail());
            }
            if (updatedUser.getPassword() != null) {
                log.debug("Updating password for user {}", id);
                user.setPassword(passwordEncoder.encode(updatedUser.getPassword()));
            }
            if (updatedUser.getFirstName() != null) user.setFirstName(updatedUser.getFirstName());
            if (updatedUser.getLastName() != null) user.setLastName(updatedUser.getLastName());
            if (updatedUser.getPhone() != null) user.setPhone(updatedUser.getPhone());

            User savedUser = userRepository.save(user);
            log.info("User updated successfully: {}", savedUser.getEmail());
            return savedUser;
        }).orElseThrow(() -> {
            log.error("User not found for update: {}", id);
            return new RuntimeException("User not found");
        });
    }

    // ОБНОВЛЯЕМ МЕТОД: Теперь он возвращает пользователя и инвалидирует токены
    public User updatePassword(String email, String newPassword) {
        log.info("Updating password for email: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.error("User not found for password update: {}", email);
                    return new RuntimeException("User not found");
                });

        user.setPassword(passwordEncoder.encode(newPassword));
        User savedUser = userRepository.save(user);

        log.info("Password updated successfully for: {}", email);
        return savedUser; // ← возвращаем пользователя
    }
}