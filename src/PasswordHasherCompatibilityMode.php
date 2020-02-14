<?php

namespace MDHearing\AspNetCore\Identity;

/**
  * Specifies the format used for hashing passwords.
  */
class PasswordHasherCompatibilityMode
{
    /**
     * Indicates hashing passwords in a way that is compatible with ASP.NET Identity versions 1 and 2.
     */
    const IdentityV2 = 2;

   /**
     * Indicates hashing passwords in a way that is compatible with ASP.NET Identity version 3.
     */
    const IdentityV3 = 3;
}

