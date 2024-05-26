import string


def caesar_cipher_encrypt(plaintext, key):
    """
    Encrypts plaintext using the Caesar cipher with the given key.

    Args:
        plaintext (str): The text to be encrypted.
        key (int): The shift value for the Caesar cipher.

    Returns:
        str: The encrypted text.
    """
    return shift_text(plaintext, key)


def caesar_cipher_decrypt(ciphertext, key):
    """
    Decrypts ciphertext using the Caesar cipher with the given key.

    Args:
        ciphertext (str): The text to be decrypted.
        key (int): The shift value for the Caesar cipher.

    Returns:
        str: The decrypted text.
    """
    return shift_text(ciphertext, -key)


def shift_text(text, key):
    """
    Shifts text by the given key using the Caesar cipher.

    Args:
        text (str): The text to be shifted.
        key (int): The shift value for the Caesar cipher.

    Returns:
        str: The shifted text.
    """
    result = []
    alphabet_lower = string.ascii_lowercase
    alphabet_upper = string.ascii_uppercase

    for c in text:
        if c in alphabet_lower:
            index = (alphabet_lower.index(c) + key) % 26
            result.append(alphabet_lower[index])
        elif c in alphabet_upper:
            index = (alphabet_upper.index(c) + key) % 26
            result.append(alphabet_upper[index])
        else:
            result.append(c)

    return ''.join(result)


def bruteforce(ciphertext):
    """
    Attempts to decrypt the given ciphertext by trying all possible keys
    and finding the one that results in the highest number of common words.

    Args:
        ciphertext (str): The text to be brute-forced.
    """
    common_words = {
        "the", "and", "have", "that", "for", "you", "with", "not", "this", "but",
        "his", "they", "her", "she", "which", "their", "will", "would", "there",
        "all", "we", "when", "your", "can", "said", "who", "get", "if", "do",
        "me", "my", "one", "what", "so", "up", "out", "about", "who", "been"
    }

    best_match_count = 0
    best_key = None
    best_decrypted_text = None

    for key in range(26):
        decrypted_text = caesar_cipher_decrypt(ciphertext, key)
        words = decrypted_text.split()
        match_count = sum(1 for word in words if word.lower() in common_words)

        if match_count > best_match_count:
            best_match_count = match_count
            best_key = key
            best_decrypted_text = decrypted_text

    if best_key is not None:
        print(f"\nLikely key (shift value): {best_key}")
        print(f"Decrypted text: {best_decrypted_text}")
    else:
        print("\nNo likely key found.")


def main():
    """
    Main function to handle user input and execute encryption, decryption,
    or brute-force attack based on user choice.
    """
    try:
        choice = int(input("Encrypt = 1, Decrypt = 2, Bruteforce = 3: "))

        if choice == 1:
            plaintext = input("Input text to encrypt: ")
            key = int(input("Input shift value: "))
            ciphertext = caesar_cipher_encrypt(plaintext, key)
            print(f"Encrypted text: {ciphertext}")

        elif choice == 2:
            ciphertext = input("Input text you want to decrypt: ")
            key = int(input("Input secret key: "))
            print(f"Decrypted text: {caesar_cipher_decrypt(ciphertext, key)}")

        elif choice == 3:
            ciphertext = input("Input ciphertext to bruteforce: ")
            bruteforce(ciphertext)

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

    except ValueError:
        print("Invalid input. Please enter a number.")

    return 0


if __name__ == "__main__":
    main()
