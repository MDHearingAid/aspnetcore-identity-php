<?php

namespace MDHearing\AspNetCore\Identity;

/**
  * Specifies the format used for hashing passwords.
  */
abstract class PasswordHasherCompatibilityMode
{
    /**
     * Indicates hashing passwords in a way that is compatible with ASP.NET Identity versions 1 and 2.
     */
    const IDENTITY_V2 = 2;

   /**
     * Indicates hashing passwords in a way that is compatible with ASP.NET Identity version 3.
     */
    const IDENTITY_V3 = 3;
}
