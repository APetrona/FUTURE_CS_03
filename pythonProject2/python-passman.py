import hashlib
import getpass
import string
import math


password_manager = {}
# List of common passwords to check against for dictionary attacks
common_passwords = ["password", "123456", "qwerty", "abc123", "letmein", "password1"]


def password_strength_checker(password):


    # Initialize report and recommendations
    report = {"strength": True, "recommendations": []}

    # Length check
    if len(password) < 12:
        report["strength"] = False
        report["recommendations"].append("Increase password length to at least 12 characters.")

    # Complexity check
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    if not (has_upper and has_lower and has_digit and has_symbol):
        report["strength"] = False
        report["recommendations"].append("Include uppercase, lowercase, digits, and symbols for stronger security.")

    # Dictionary attack check
    if password.lower() in common_passwords:
        report["strength"] = False
        report["recommendations"].append("Avoid using common passwords or dictionary words.")


    char_space = 0
    if has_lower: char_space += 26
    if has_upper: char_space += 26
    if has_digit: char_space += 10
    if has_symbol: char_space += len(string.punctuation)

    entropy = len(password) * math.log2(char_space) if char_space else 0
    time_to_crack = 2 ** entropy / 1e9  # Estimated brute-force time (1 billion guesses per second)


    if time_to_crack < 86400:  # 86400 seconds in a day
        report["strength"] = False
        report["recommendations"].append("Increase complexity to make brute-force attacks harder.")

    return report


def create_account():
    username = input("Enter your desired username: ")

    while True:
        password = getpass.getpass("Enter your desired password: ")
        strength_report = password_strength_checker(password)

        if strength_report["strength"]:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            password_manager[username] = hashed_password
            print("Account created successfully!")
            break
        else:
            print("Password is too weak. Here are some recommendations to improve it:")
            for recommendation in strength_report["recommendations"]:
                print(f"- {recommendation}")
            print("Please try a stronger password.")


def login():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if username in password_manager and password_manager[username] == hashed_password:
        print("Login successful!")
    else:
        print("Login failed. Incorrect username or password.")


def main():
    while True:
        choice = input(
            "Enter 1 to create an account, 2 to login, or 0 to exit: ").strip().upper()
        if choice == "1":
            create_account()
        elif choice == "2":
            login()
        elif choice == "0":
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
