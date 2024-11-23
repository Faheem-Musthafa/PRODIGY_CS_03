import re
import math

def calculate_entropy(password):
    """Calculate password entropy based on its character set."""
    character_sets = {
        'lowercase': r'[a-z]',
        'uppercase': r'[A-Z]',
        'digits': r'\d',
        'special': r'[!@#$%^&*(),.?":{}|<>]',
    }
    
    pool_size = 0
    for char_set, regex in character_sets.items():
        if re.search(regex, password):
            if char_set == 'lowercase' or char_set == 'uppercase':
                pool_size += 26
            elif char_set == 'digits':
                pool_size += 10
            elif char_set == 'special':
                pool_size += len('!@#$%^&*(),.?":{}|<>')
    
    entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0
    return entropy

def password_complexity_checker(password):
    feedback = []
    score = 0

    # Rule 1: Length of the password
    if len(password) >= 16:
        score += 3
        feedback.append("Excellent length (16+ characters).")
    elif 12 <= len(password) < 16:
        score += 2
        feedback.append("Strong length (12-15 characters).")
    elif 8 <= len(password) < 12:
        score += 1
        feedback.append("Good length (8-11 characters).")
    else:
        feedback.append("Weak length (less than 8 characters). Consider a longer password.")

    # Rule 2: Uppercase letters
    if re.search(r'[A-Z]', password):
        score += 1
        feedback.append("Contains uppercase letters.")
    else:
        feedback.append("Missing uppercase letters. Add at least one uppercase letter.")

    # Rule 3: Lowercase letters
    if re.search(r'[a-z]', password):
        score += 1
        feedback.append("Contains lowercase letters.")
    else:
        feedback.append("Missing lowercase letters. Add at least one lowercase letter.")

    # Rule 4: Numbers
    if re.search(r'\d', password):
        score += 1
        feedback.append("Contains numbers.")
    else:
        feedback.append("Missing numbers. Add at least one numeric digit.")

    # Rule 5: Special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 2
        feedback.append("Contains special characters (e.g., @, #, $).")
    else:
        feedback.append("Missing special characters. Add at least one special character.")

    # Rule 6: Avoid patterns like "aaa" or "123"
    if re.search(r'(.)\1{2,}', password):
        feedback.append("Avoid repeated characters (e.g., 'aaa').")
    if re.search(r'(012|123|234|345|456|567|678|789)', password):
        feedback.append("Avoid sequential numbers (e.g., '123').")

    # Rule 7: Entropy check
    entropy = calculate_entropy(password)
    if entropy >= 60:
        feedback.append("Entropy is high, indicating a strong password.")
    elif 40 <= entropy < 60:
        feedback.append("Entropy is moderate. Add more character types or increase length.")
    else:
        feedback.append("Entropy is low. Use a longer and more complex password.")

    # Final evaluation
    if score >= 8:
        feedback.append("Password strength: Excellent.")
    elif 5 <= score < 8:
        feedback.append("Password strength: Good. Can be improved further.")
    else:
        feedback.append("Password strength: Weak. Consider the recommendations above.")

    return feedback

# Example usage
password = input("Enter a password to test: ")
result = password_complexity_checker(password)

print("\nPassword Feedback:")
for line in result:
    print(f"- {line}")
