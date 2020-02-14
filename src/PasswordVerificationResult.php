<?php

namespace MDHearing\AspNetCore\Identity;

/**
 * Specifies the results for password verification.
 */
abstract class PasswordVerificationResult
{
    /**
     * Indicates password verification failed.
     */
    const FAILED = 0;

    /**
     * Indicates password verification was successful.
     */
    const SUCCESS = 1;

    /**
     * Indicates password verification was successful however the password was encoded using a deprecated algorithm
     * and should be rehashed and updated.
     */
    const SUCCESS_REHASH_NEEDED = 2;
}
