SHA256-Book-of-Mark-Implementation
📘 Project Overview

This project implements the SHA-256 cryptographic hash algorithm in C++, based on the pseudocode provided on the official SHA-2 Wikipedia page.
The algorithm is used here to compute a hash value for the entire Book of Mark, demonstrating how message digest algorithms can be used for data verification and integrity checking.

🧠 Purpose

This assignment focuses on understanding how cryptographic hashing algorithms, such as SHA-256, function internally.
It involves implementing:

Bitwise operations (XOR, AND, NOT, rotate right)

Message preprocessing (padding)

Chunk-based message compression

Final digest computation (256-bit hash)

⚙️ Implementation Details

Language: C++17

Algorithm: SHA-256

Input: Full text of the Book of Mark (mark_text_cleaned.txt)

Output: 64-character hexadecimal hash string (MARK_SHA256_cleaned.txt)

The code follows the SHA-2 specification with:

Initialization of constants derived from prime roots

64 rounds of compression using bitwise operations

Modular arithmetic (mod 2³²) for all additions
