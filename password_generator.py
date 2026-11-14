"""
Password Generator
Generates a strong random password of the length and complexity you choose.
Uses the `secrets` module (cryptographically secure), not `random`.
"""

import secrets
import string

MIN_LENGTH = 4
MAX_LENGTH = 128

CHAR_SETS = {
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+[]{};:,.<>?/",
}

# Complexity levels -> which character sets they include
LEVELS = {
    "1": ("Low (letters only)", ["lowercase", "uppercase"]),
    "2": ("Medium (letters + digits)", ["lowercase", "uppercase", "digits"]),
    "3": ("High (letters + digits + symbols)",
          ["lowercase", "uppercase", "digits", "symbols"]),
}


def generate_password(length, set_names):
    """Build a password containing at least one character from every chosen set."""
    if length < len(set_names):
        raise ValueError("Length is too short for the chosen complexity")

    # One guaranteed character from each selected set
    chars = [secrets.choice(CHAR_SETS[name]) for name in set_names]

    # Fill the rest from the combined pool
    pool = "".join(CHAR_SETS[name] for name in set_names)
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]

    # Shuffle so the guaranteed characters are not always at the start
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def strength_label(length, set_names):
    if length >= 16 and len(set_names) >= 3:
        return "Very strong"
    if length >= 12 and len(set_names) >= 3:
        return "Strong"
    if length >= 8 and len(set_names) >= 2:
        return "Moderate"
    return "Weak"


def read_length():
    while True:
        try:
            length = int(input(f"Enter password length ({MIN_LENGTH}-{MAX_LENGTH}): "))
            if MIN_LENGTH <= length <= MAX_LENGTH:
                return length
            print(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")
        except ValueError:
            print("Please enter a whole number.")


def read_level():
    print("\nChoose complexity:")
    for key, (label, _) in LEVELS.items():
        print(f"  {key}. {label}")
    while True:
        choice = input("Enter choice (1-3): ").strip()
        if choice in LEVELS:
            return LEVELS[choice][1]
        print("Invalid choice. Please select 1, 2 or 3.")


def main():
    print("=== PASSWORD GENERATOR ===\n")
    while True:
        length = read_length()
        set_names = read_level()

        password = generate_password(length, set_names)
        print(f"\nGenerated password: {password}")
        print(f"Strength: {strength_label(length, set_names)}")

        if input("\nGenerate another? (y/n): ").strip().lower() != "y":
            print("Stay safe online!")
            break
        print()


if __name__ == "__main__":
    main()
