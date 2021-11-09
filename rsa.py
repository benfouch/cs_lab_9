"""
- CS2911 - 011
- Fall 2021
- Lab 9 - RSA Encryption
- Names:
  - Nathan Cernik
  - Ben Fouch
  - Aidan Regan

16-bit RSA

Introduction: (Describe the lab in your own words)
This lab is to teach us how RSA encryption and brute force attacks work.

Question 1: RSA Security
In this lab, Trudy is able to find the private key from the public key. Why is this not a problem for RSA in practice?
The keys in this lab are much smaller than ones used in real practice. These can be broken quickly while the real keys
used in proactive are computationally infeasible to break

Question 2: Critical Step(s)
When creating a key, Bob follows certain steps. Trudy follows other steps to break a key. What is the difference between
 Bob’s steps and Trudy’s so that Bob is able to run his steps on large numbers, but Trudy cannot run her steps on large
 numbers?

Trudy does not know as much as bob does. He is able to fill out more of the equation and simply get results, while trudy
has to try multiple iterations for the equation to guess what the correct answer is. If she were to try that with large
numbers, it would never finish

Checksum Activity:
Provide a dicussion of your experiences as described in the activity.  Be sure to answer all questions.
How can trudy be stopped in this instance:
The checksum here only adds the unicode value for each char in the string, that allows for any of the chars to be moved
around. This would give a new value for the message, but would have the same checksum.
She can be stopped from doing this by us implementing a new checksum algorithm. Possibly one that mulltiples the
position index by the value of the char, and then adding it. This would still in theroy allow for other messages, but
very rarely any that would make any sense

Summary: (Summarize your experience with the lab, what you learned, what you liked,what you disliked, and any suggestions you have for improvement)
This was a fun lab. It was definitely needed to help the understanding of how the algorithms work. It can be hard to
understand how this all works until you try to implement it. We dont have any suggestions, the proved code was a great
starting place for the lab and helped to keep us focused on the parts that actually related to the course work.
"""

import random
import sys

# Use these named constants as you write your code
MAX_PRIME = 0b11111111  # The maximum value a prime number can have
MIN_PRIME = 0b11000001  # The minimum value a prime number can have 
PUBLIC_EXPONENT = 17  # The default public exponent


def main():
    """ Provide the user with a variety of encryption-related actions """

    # Get chosen operation from the user.
    action = input("Select an option from the menu below:\n"
                   "(1-CK) create_keys\n"
                   "(2-CC) compute_checksum\n"
                   "(3-VC) verify_checksum\n"
                   "(4-EM) encrypt_message\n"
                   "(5-DM) decrypt_message\n"
                   "(6-BK) break_key\n "
                   "Please enter the option you want:\n")
    # Execute the chosen operation.
    if action in ['1', 'CK', 'ck', 'create_keys']:
        create_keys_interactive()
    elif action in ['2', 'CC', 'cc', 'compute_checksum']:
        compute_checksum_interactive()
    elif action in ['3', 'VC', 'vc', 'verify_checksum']:
        verify_checksum_interactive()
    elif action in ['4', 'EM', 'em', 'encrypt_message']:
        encrypt_message_interactive()
    elif action in ['5', 'DM', 'dm', 'decrypt_message']:
        decrypt_message_interactive()
    elif action in ['6', 'BK', 'bk', 'break_key']:
        break_key_interactive()
    else:
        print("Unknown action: '{0}'".format(action))


def create_keys_interactive():
    """
    Create new public keys

    :return: the private key (d, n) for use by other interactive methods
    """

    key_pair = create_keys()
    pub = get_public_key(key_pair)
    priv = get_private_key(key_pair)
    print("Public key: ")
    print(pub)
    print("Private key: ")
    print(priv)
    return priv


def compute_checksum_interactive():
    """
    Compute the checksum for a message, and encrypt it
    """

    priv = create_keys_interactive()

    message = input('Please enter the message to be checksummed: ')

    hash_code = compute_checksum(message)
    print('Hash:', "{0:04x}".format(hash_code))
    cipher = apply_key(priv, hash_code)
    print('Encrypted Hash:', "{0:04x}".format(cipher))


def verify_checksum_interactive():
    """
    Verify a message with its checksum, interactively
    """

    pub = enter_public_key_interactive()
    message = input('Please enter the message to be verified: ')
    recomputed_hash = compute_checksum(message)

    string_hash = input('Please enter the encrypted hash (in hexadecimal): ')
    encrypted_hash = int(string_hash, 16)
    decrypted_hash = apply_key(pub, encrypted_hash)
    print('Recomputed hash:', "{0:04x}".format(recomputed_hash))
    print('Decrypted hash: ', "{0:04x}".format(decrypted_hash))
    if recomputed_hash == decrypted_hash:
        print('Hashes match -- message is verified')
    else:
        print('Hashes do not match -- has tampering occured?')


def encrypt_message_interactive():
    """
    Encrypt a message
    """

    message = input('Please enter the message to be encrypted: ')
    pub = enter_public_key_interactive()
    encrypted = ''
    for c in message:
        encrypted += "{0:04x}".format(apply_key(pub, ord(c)))
    print("Encrypted message:", encrypted)


def decrypt_message_interactive(priv=None):
    """
    Decrypt a message
    """

    encrypted = input('Please enter the message to be decrypted: ')
    if priv is None:
        priv = enter_key_interactive('private')
    message = ''
    for i in range(0, len(encrypted), 4):
        enc_string = encrypted[i:i + 4]
        enc = int(enc_string, 16)
        dec = apply_key(priv, enc)
        if 0 <= dec < 256:
            message += chr(dec)
        else:
            print('Warning: Could not decode encrypted entity: ' + enc_string)
            print('         decrypted as: ' + str(dec) + ' which is out of range.')
            print('         inserting _ at position of this character')
            message += '_'
    print("Decrypted message:", message)


def break_key_interactive():
    """
    Break key, interactively
    """

    pub = enter_public_key_interactive()
    priv = break_key(pub)
    print("Private key:")
    print(priv)
    decrypt_message_interactive(priv)


def enter_public_key_interactive():
    """
    Prompt user to enter the public modulus.

    :return: the tuple (e,n)
    """

    print('(Using public exponent = ' + str(PUBLIC_EXPONENT) + ')')
    string_modulus = input('Please enter the modulus (decimal): ')
    modulus = int(string_modulus)
    return PUBLIC_EXPONENT, modulus


def enter_key_interactive(key_type):
    """
    Prompt user to enter the exponent and modulus of a key

    :param key_type: either the string 'public' or 'private' -- used to prompt the user on how
                     this key is interpretted by the program.
    :return: the tuple (e,n)
    """
    string_exponent = input('Please enter the ' + key_type + ' exponent (decimal): ')
    exponent = int(string_exponent)
    string_modulus = input('Please enter the modulus (decimal): ')
    modulus = int(string_modulus)
    return exponent, modulus


def compute_checksum(string):
    """
    Compute simple hash

    Given a string, compute a simple hash as the sum of characters
    in the string.

    (If the sum goes over sixteen bits, the numbers should "wrap around"
    back into a sixteen bit number.  e.g. 0x3E6A7 should "wrap around" to
    0xE6A7)

    This checksum is similar to the internet checksum used in UDP and TCP
    packets, but it is a two's complement sum rather than a one's
    complement sum.

    :param str string: The string to hash
    :return: the checksum as an integer
    """

    total = 0
    for c in string:
        total += ord(c)
    total %= 0x8000  # Guarantees checksum is only 4 hex digits
    # How many bytes is that?
    #
    # Also guarantees that that the checksum will
    # always be less than the modulus.
    return total


# ---------------------------------------
# Do not modify code above this line
# ---------------------------------------

def create_keys():
    """
    :Author: Nate Cernik
    """
    e = PUBLIC_EXPONENT
    p = prime_generator(e)
    q = prime_generator(e)
    while p == q:
        q = prime_generator(e)
    n = p * q
    z = (p - 1) * (q - 1)
    d = apply_euclid_method(e, z)
    return e, d, n


def prime_generator(e):
    """
    :Author: Aiden Regan
    """
    random_num = random_num_generator()
    while (not is_num_co_prime(random_num, e)) | (not is_prime(random_num)):
        return random_num_generator()


def random_num_generator():
    """
    :Author: Aiden Regan
    """
    return random.randint(MIN_PRIME, MAX_PRIME) | 1


def is_prime(num):
    """
    :Author: Aiden Regan
    """
    for i in range(2, num):
        if num % i == 0:
            return False
    return True


def is_num_co_prime(num, e):
    """
    :Author: Aiden Regan
    """
    return (num - 1) % e != 0


def apply_euclid_method(e, z):
    """
    :Author: Nate Cernik
    """
    d = 0
    r = z
    newd = 1
    newr = e
    while newr != 0:
        quotient = r // newr
        (d, newd) = (newd, d - quotient * newd)
        (r, newr) = (newr, r - quotient * newr)
    if r > 1:
        return "a is not invertible"
    if d < 0:
        d = d + z
    return d


def apply_key(key, m):
    """
    :Author: Ben Fouch
    """
    k, n = key
    if 37249 < n < 65025:
        return (m ** k) % n
    else:
        print("Incorrect Public Key Value.")
        exit()


def break_key(pub):
    """
    :Author: Ben Fouch
    """
    e, n = pub
    p, q = get_prime_factors(n)
    z = (p - 1) * (q - 1)
    d = apply_euclid_method(e, z)
    return d, n


def get_prime_factors(n):
    """
    :Author: Nate Cernik
    """
    for i in range(MIN_PRIME, MAX_PRIME + 1, 2):
        if is_prime(i) & ((n % i) == 0):
            num = n // i
            return i, num


# ---------------------------------------
# Do not modify code below this line
# ---------------------------------------


def get_public_key(key_pair):
    """
    Pulls the public key out of the tuple structure created by
    create_keys()

    :param key_pair: (e,d,n)
    :return: (e,n)
    """

    return key_pair[0], key_pair[2]


def get_private_key(key_pair):
    """
    Pulls the private key out of the tuple structure created by
    create_keys()

    :param key_pair: (e,d,n)
    :return: (d,n)
    """

    return key_pair[1], key_pair[2]


main()