﻿# PRODIGY_CS_03

# Advanced Password Complexity Checker 🔒

The **Advanced Password Complexity Checker** is a Python-based tool that evaluates the strength of passwords based on multiple criteria, including length, diversity of characters, entropy, and patterns. It provides detailed feedback to help users create stronger, more secure passwords.

---

## Features 🛠️

- **Length Validation:** Scores passwords based on their length.
- **Character Diversity:** Checks for the presence of uppercase, lowercase, numbers, and special characters.
- **Entropy Calculation:** Estimates the strength of the password using entropy.
- **Pattern Detection:** Identifies weaknesses like repeated characters (e.g., `aaa`) or sequential numbers/letters (e.g., `123` or `abc`).
- **Actionable Feedback:** Provides tips for improving weak passwords.
- **Strength Evaluation:** Categorizes passwords as *Weak*, *Good*, or *Excellent*.

---

## Prerequisites ⚙️

Before running the project, make sure you have the following installed:

- **Python 3.6+**

---

## Installation 📦

1. Clone the repository:
   ```bash
   git clone https://github.com/Faheem-Musthafa/PRODIGY_CS_03.git
   cd password-complexity-checker
   ```

2. (Optional) Set up a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use: venv\Scripts\activate
   ```

3. Install dependencies:
   No additional dependencies are required; the project runs with Python's standard libraries.

---

## Usage 🚀

1. Run the script:
   ```bash
   python password_complexity_checker.py
   ```

2. Enter a password when prompted:
   ```
   Enter a password to test: MyP@ssword123
   ```

3. View detailed feedback:
   ```
   Password Feedback:
   - Good length (8-11 characters).
   - Contains uppercase letters.
   - Contains lowercase letters.
   - Contains numbers.
   - Contains special characters (e.g., @, #, $).
   - Entropy is moderate. Add more character types or increase length.
   - Password strength: Good. Can be improved further.
   ```

---

## Example Output 📝

Here's an example of how the tool evaluates passwords:

### Input:  
`MySecureP@ssw0rd!`

### Output:
```
Password Feedback:
- Excellent length (16+ characters).
- Contains uppercase letters.
- Contains lowercase letters.
- Contains numbers.
- Contains special characters (e.g., @, #, $).
- Entropy is high, indicating a strong password.
- Password strength: Excellent.
```

---

## Contributing 🤝

Contributions are welcome! If you have ideas for additional features or improvements, feel free to:

1. Fork this repository.
2. Create a new branch (`git checkout -b feature-new-feature`).
3. Commit your changes (`git commit -m 'Add a new feature'`).
4. Push to the branch (`git push origin feature-new-feature`).
5. Open a pull request.

---

## Future Enhancements 🌟

- Add GUI support for better usability.
- Integrate with APIs to check for breached passwords.
- Extend character set analysis to detect Unicode and international symbols.
- Build a web-based version for broader accessibility.

---

## Contact 📧

If you have any questions or need assistance, feel free to contact me:

- **Email:** faheemmusthafa241@gmail.com
- **GitHub:** [Faheem Musthafa](https://github.com/Faheem-Musthafa)

---

### Happy Coding! 👨‍💻
