# ChaCha20-Poly1305-SIV
ChaCha20-Poly1305-SIV (CCP-SIV) is a misuse-resistant, key-committing AEAD scheme. It is built from ChaCha20 and Poly1305 without modifying their designs, making it compatible with existing APIs from cryptographic libraries. Furthermore, the overhead is just two ChaCha20 blocks over ChaCha20-Poly1305 whilst supporting a larger nonce.

More information can be found in the [C2SP draft spec](https://github.com/C2SP/C2SP/pull/130).

> [!CAUTION]
> This design has not received any peer review or proper analysis yet. Therefore, it **MUST NOT** be used in production until this situation has been rectified and there is confidence in the design.
