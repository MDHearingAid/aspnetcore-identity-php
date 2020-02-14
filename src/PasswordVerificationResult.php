<?php

namespace MDHearing\AspNetCore\Identity;

/**
 * Specifies the results for password verification.
 */
class PasswordVerificationResult
{
    /**
     * Indicates password verification failed.
     */
    const Failed = 0;

    /**
     * Indicates password verification was successful.
     */
    const Success = 1;

    /**
     * Indicates password verification was successful however the password was encoded using a deprecated algorithm
     * and should be rehashed and updated.
     */
    const SuccessRehashNeeded = 2;
}

