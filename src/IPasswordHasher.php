<?php

namespace MDHearing\AspNetCore\Identity;

/**
 * Provides an abstraction for hashing passwords.
 */
interface IPasswordHasher
{
    /**
      * Returns a hashed representation of the supplied password.
      *
      * @param $password The password to hash.
      *
      * @returns A hashed representation of the supplied password.
      */
    public function hashPassword($password);

    /**
      * Returns a PasswordVerificationResult indicating the result of a password hash comparison.
      *
      * @param $hashedPassword The hash value for a user's stored password.
      * @param $providedPassword The password supplied for comparison.
      *
      * @returns A PasswordVerificationResult indicating the result of a password hash comparison.
      */
    public function verifyHashedPassword($hashedPassword, $providedPassword);
}
