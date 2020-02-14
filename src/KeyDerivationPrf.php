<?php

namespace MDHearing\AspNetCore\Identity;

abstract class KeyDerivationPrf
{
    /**
     * The HMAC algorithm (RFC 2104) using the SHA-1 hash function (FIPS 180-4).
     */
    const HMACSHA1 = 0;

    /**
     * The HMAC algorithm (RFC 2104) using the SHA-256 hash function (FIPS 180-4).
     */
    const HMACSHA256 = 1;

    /**
     * The HMAC algorithm (RFC 2104) using the SHA-512 hash function (FIPS 180-4).
     */
    const HMACSHA512 = 2;

    /**
     * Map of algorithm keys.
     */
    const ALGO_NAME = [
        self::HMACSHA1 => 'sha1',
        self::HMACSHA256 => 'sha256',
        self::HMACSHA512 => 'sha512'
    ];
}

