<?php

namespace MDHearing\AspNetCore\Identity;

use InvalidArgumentException;

/**
 * Implements the standard Identity password hashing.
 */
class PasswordHasher implements IPasswordHasher
{
    /* =======================
     * HASHED PASSWORD FORMATS
     * =======================
     *
     * Version 2:
     * PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.
     * (See also: SDL crypto guidelines v5.1, Part III)
     * Format: { 0x00, salt, subkey }
     *
     * Version 3:
     * PBKDF2 with HMAC-SHA256, 128-bit salt, 256-bit subkey, 10000 iterations.
     * Format: { 0x01, prf (UInt32), iter count (UInt32), salt length (UInt32), salt, subkey }
     * (All UInt32s are stored big-endian.)
     */

    private $compatibilityMode;
    private $iterCount;

    /**
      * Creates a new instance of <see cref="PasswordHasher{TUser}"/>.
      *
      * @param $optionsAccessor The options for this instance.
      */
    public function __construct(
        $compatibilityMode = PasswordHasherCompatibilityMode::IDENTITY_V3,
        $iterationsCount = 10000
    ) {
        $this->compatibilityMode = $compatibilityMode;
        switch ($this->compatibilityMode) {
            case PasswordHasherCompatibilityMode::IDENTITY_V2:
                // nothing else to do
                break;

            case PasswordHasherCompatibilityMode::IDENTITY_V3:
                $this->iterCount = $iterationsCount;
                if ($this->iterCount < 1) {
                    throw new InvalidArgumentException('Invalid password hasher iteration count.');
                }
                break;

            default:
                throw new InvalidArgumentException('Invalid password hasher compatibility mode.');
        }
    }

    /**
      * Returns a hashed representation of the supplied <paramref name="password"/>
      * for the specified <paramref name="user"/>.
      *
      * @param $password The password to hash.
      *
      * @returns A hashed representation of the supplied password for the specified user.
      */
    public function hashPassword($password)
    {
        if ($password == null) {
            throw new InvalidArgumentException('Password cannot be null');
        }

        if ($this->compatibilityMode == PasswordHasherCompatibilityMode::IDENTITY_V2) {
            return base64_encode(static::hashPasswordV2($password));
        } else {
            return base64_encode($this->hashPasswordV3($password));
        }
    }

    private static function hashPasswordV2($password)
    {
        $Pbkdf2Prf = KeyDerivationPrf::HMACSHA1; // default for Rfc2898DeriveBytes
        $Pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
        $Pbkdf2SubkeyLength = intdiv(256, 8); // 256 bits
        $SaltSize = intdiv(128, 8); // 128 bits

        // Produce a version 2 (see comment above) text hash.
        $salt = random_bytes($SaltSize);
        $subkey = hash_pbkdf2(
            KeyDerivationPrf::ALGO_NAME[$Pbkdf2Prf],
            $password,
            $salt,
            $Pbkdf2IterCount,
            $Pbkdf2SubkeyLength,
            true
        );

        $outputBytes = chr(0) . $salt . $subkey;

        return $outputBytes;
    }

    private function hashPasswordV3($password)
    {
        $prf = KeyDerivationPrf::HMACSHA256;
        $iterCount = $this->iterCount;
        $saltSize = intdiv(128, 8);
        $numBytesRequested = intdiv(256, 8);

        // Produce a version 3 (see comment above) text hash.
        $salt = random_bytes($saltSize);
        $subkey = hash_pbkdf2(
            KeyDerivationPrf::ALGO_NAME[$prf],
            $password,
            $salt,
            $iterCount,
            $numBytesRequested,
            true
        );

        $outputBytes = '';
        $outputBytes[0] = chr(0x01); // format marker
        static::WriteNetworkByteOrder($outputBytes, 1, $prf);
        static::WriteNetworkByteOrder($outputBytes, 5, $iterCount);
        static::WriteNetworkByteOrder($outputBytes, 9, $saltSize);

        $outputBytes .= $salt;
        $outputBytes .= $subkey;

        return $outputBytes;
    }

    /**
      * Returns a PasswordVerificationResult indicating the result of a password hash comparison.
      *
      * @param $hashedPassword The hash value for a user's stored password.
      * @param $providedPassword The password supplied for comparison.
      *
      * @returns A PasswordVerificationResult indicating the result of a password hash comparison.
      *
      * Implementations of this method should be time consistent.
      */
    public function verifyHashedPassword($hashedPassword, $providedPassword)
    {
        if ($hashedPassword == null) {
            throw new InvalidArgumentException('hashedPassword is null');
        }

        if ($providedPassword == null) {
            throw new InvalidArgumentException('providedPassword is null');
        }

        $decodedHashedPassword = base64_decode($hashedPassword);

        // read the format marker from the hashed password
        if (strlen($decodedHashedPassword) == 0) {
            return PasswordVerificationResult::FAILED;
        }

        switch (ord($decodedHashedPassword[0])) {
            case 0x00:
                return $this->verifyWithV2($decodedHashedPassword, $providedPassword);
            case 0x01:
                return $this->verifyWithV3($decodedHashedPassword, $providedPassword);
            default:
                return PasswordVerificationResult::FAILED; // unknown format marker
        }
    }

    /**
     * Performs verification using strategy version 2.
     *
     * @param  string $decodedHashedPassword
     * @param  string $providedPassword
     * @return integer
     */
    private function verifyWithV2($decodedHashedPassword, $providedPassword)
    {
        if (static::verifyHashedPasswordV2($decodedHashedPassword, $providedPassword)) {
            // This is an old password hash format - the caller needs to
            // rehash if we're not running in an older compat mode.
            return ($this->compatibilityMode == PasswordHasherCompatibilityMode::IDENTITY_V3)
                ? PasswordVerificationResult::SUCCESS_REHASH_NEEDED
                : PasswordVerificationResult::SUCCESS;
        } else {
            return PasswordVerificationResult::FAILED;
        }
    }

    /**
     * Performs verification using strategy version 3.
     *
     * @param  string $decodedHashedPassword
     * @param  string $providedPassword
     * @return integer
     */
    private function verifyWithV3($decodedHashedPassword, $providedPassword)
    {
        $embeddedIterCount = null;

        if (static::verifyHashedPasswordV3($decodedHashedPassword, $providedPassword, $embeddedIterCount)) {
            // If this hasher was configured with a higher iteration count, change the entry now.
            return ($embeddedIterCount < $this->iterCount)
                ? PasswordVerificationResult::SUCCESS_REHASH_NEEDED
                : PasswordVerificationResult::SUCCESS;
        } else {
            return PasswordVerificationResult::FAILED;
        }
    }

    private static function verifyHashedPasswordV2($hashedPassword, $password)
    {
        $Pbkdf2Prf = KeyDerivationPrf::HMACSHA1; // default for Rfc2898DeriveBytes
        $Pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
        $Pbkdf2SubkeyLength = intdiv(256, 8); // 256 bits
        $SaltSize = intdiv(128, 8); // 128 bits

        // We know ahead of time the exact length of a valid hashed password payload.
        if (strlen($hashedPassword) != 1 + $SaltSize + $Pbkdf2SubkeyLength) {
            return false; // bad size
        }

        $salt = substr($hashedPassword, 1, $SaltSize);

        $expectedSubkey = substr($hashedPassword, 1 + $SaltSize, $Pbkdf2SubkeyLength);

        // Hash the incoming password and verify it
        $actualSubkey = hash_pbkdf2(
            KeyDerivationPrf::ALGO_NAME[$Pbkdf2Prf],
            $password,
            $salt,
            $Pbkdf2IterCount,
            $Pbkdf2SubkeyLength,
            true
        );

        return $actualSubkey === $expectedSubkey;
    }

    private static function verifyHashedPasswordV3($hashedPassword, $password, &$iterCount)
    {
        $iterCount = 0;

        // Read header information
        $prf = static::readNetworkByteOrder($hashedPassword, 1);
        $iterCount = static::readNetworkByteOrder($hashedPassword, 5);
        $saltLength = static::readNetworkByteOrder($hashedPassword, 9);

        // Read the salt: must be >= 128 bits
        if ($saltLength < intdiv(128, 8)) {
            return false;
        }

        $salt = substr($hashedPassword, 13, $saltLength);

        // Read the subkey (the rest of the payload): must be >= 128 bits
        $subkeyLength = strlen($hashedPassword) - 13 - strlen($salt);
        if ($subkeyLength < intdiv(128, 8)) {
            return false;
        }

        $expectedSubkey = substr($hashedPassword, 13 + strlen($salt), $subkeyLength);

        // Hash the incoming password and verify it
        $actualSubkey = hash_pbkdf2(
            KeyDerivationPrf::ALGO_NAME[$prf],
            $password,
            $salt,
            $iterCount,
            $subkeyLength,
            true
        );

        return $actualSubkey === $expectedSubkey;
    }

    private static function writeNetworkByteOrder(&$buffer, $offset, $value)
    {
        $buffer[$offset] = chr($value >> 24);
        $buffer[$offset + 1] = chr(($value >> 16) & 0xFF);
        $buffer[$offset + 2] = chr(($value >> 8) & 0xFF);
        $buffer[$offset + 3] = chr($value & 0xFF);
    }

    private static function readNetworkByteOrder($buffer, $offset)
    {
        return ord($buffer[$offset]) << 24
            | ord($buffer[$offset + 1]) << 16
            | ord($buffer[$offset + 2]) << 8
            | ord($buffer[$offset + 3]);
    }
}
