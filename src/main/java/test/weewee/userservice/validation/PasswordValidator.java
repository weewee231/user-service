package test.weewee.userservice.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordValidator implements ConstraintValidator<ValidPassword, String> {

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null || password.length() < 8) {
            return false;
        }

        // Проверяем наличие хотя бы одной цифры
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        // Проверяем наличие хотя бы одной буквы
        boolean hasLetter = password.chars().anyMatch(Character::isLetter);
        // Проверяем отсутствие пробелов
        boolean noSpaces = !password.contains(" ");

        return hasDigit && hasLetter && noSpaces;
    }
}