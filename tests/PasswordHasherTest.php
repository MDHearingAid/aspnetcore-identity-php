<?php

declare(strict_types=1);

namespace MDHearing\AspNetCore\Identity;

use InvalidArgumentException;

class PasswordHasherTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Test invalid compatibility.
     */
    public function testInvalidCompatibility()
    {
        $this->expectException(InvalidArgumentException::class);
        $hasher = new PasswordHasher(4);
    }

    /**
     * Test invalid password hashing.
     */
    public function testInvalidPasswordHashing()
    {
        $this->expectException(InvalidArgumentException::class);
        $hasher = new PasswordHasher();
        $hashedPassword = $hasher->hashPassword(null);
    }

    /**
     * Test invalid password hash verification.
     */
    public function testInvalidPasswordHashVerification()
    {
        $this->expectException(InvalidArgumentException::class);
        $hasher = new PasswordHasher();
        $hashedPassword = $hasher->verifyHashedPassword(null, 'very strong password');
    }

    /**
     * Test invalid password verification.
     */
    public function testInvalidPasswordVerification()
    {
        $this->expectException(InvalidArgumentException::class);
        $hasher = new PasswordHasher();
        $hashedPassword = $hasher->verifyHashedPassword('very strong hash', null);
    }

    /**
     * Test some basic v2 password hashing.
     */
    public function testHashV2Passwords()
    {
        $hasher = new PasswordHasher(PasswordHasherCompatibilityMode::IDENTITY_V2);
        $hashedPassword = $hasher->hashPassword('very strong password');
        $result = $hasher->verifyHashedPassword($hashedPassword, 'very strong password');
        $this->assertEquals(PasswordVerificationResult::SUCCESS, $result);
    }

    /**
     * Test insufficient v3 iteration count.
     */
    public function testInsufficientV3IterationCount()
    {
        $this->expectException(InvalidArgumentException::class);
        $hasher = new PasswordHasher(PasswordHasherCompatibilityMode::IDENTITY_V3, 0);
    }

    /**
     * Test some basic v3 password hashing.
     */
    public function testHashV3Passwords()
    {
        $hasher = new PasswordHasher();
        $hashedPassword = $hasher->hashPassword('very strong password');
        $result = $hasher->verifyHashedPassword($hashedPassword, 'very strong password');
        $this->assertEquals(PasswordVerificationResult::SUCCESS, $result);
    }

    /**
     * Test some basic v3 hashed passwords.
     */
    public function testVerifyV3Passwords()
    {
        $hasher = new PasswordHasher();
        $tests = [
            [
                'password' => 'simpletext',
                'hash' => 'AQAAAAEAACcQAAAAEMyYfEM68Uhlq3hGyZfiCrhr1no1wBo+hbpJKIDj+hkWU1J7HK7did6j4OUW2JUWtQ==',
                'expected' => 1
            ],
            [
                'password' => 's1s2s3s4s5',
                'hash' => 'AQAAAAEAACcQAAAAEH4yPc6icjaK6hwW2IcgcYQvRapfV8Pu6ReeUBYo9BK940Cs0EE27z4pqNjFNx1a7A==',
                'expected' => 1
            ],
            [
                'password' => '$r5_0099GG',
                'hash' => 'AQAAAAEAACcQAAAAELHi5x35J21vX7PrJpkLV3Cpcrq77UT8ugOME4yQQRKtLme0yHVRCRE3g25vUcU+0Q==',
                'expected' => 1
            ],
            [
                'password' => '00000000',
                'hash' => 'AQAAAAEAACcQAAAAENEJN/6KmFhZSKU2FAbQXJ8W/Jezj+nVcIWaaN0bX5eFtZJ/YZJODPzSNk+osfctNA==',
                'expected' => 1
            ],
            [
                'password' => '!@#$%^&*()',
                'hash' => 'AQAAAAEAACcQAAAAEDOH4CuyIUZEPgLd/5lQuCfwBwQJjEmx+wx2UThr8gOJfqYIt+RsmQ9DxyrRLOwb4Q==',
                'expected' => 1
            ],
            [
                'password' => '<<<<>>>>',
                'hash' => 'AQAAAAEAACcQAAAAEEO69RdpcrgHOsvb+Jq0+os2P+T6O8W8Ui7uA/1+iw10CqY+K1pct8iMVCghqpybLg==',
                'expected' => 1
            ],
            [
                'password' => ';;;;;;;;',
                'hash' => 'AQAAAAEAACcQAAAAEFYxv5ajw5AQ3X7f71oIntlhSVx9nShSkZspqL9qJzkh5gkK4DGQyekkXS+SquKlgw==',
                'expected' => 1
            ]
        ];

        foreach ($tests as $test) {
            $original = $test;

            $test['actual']     = $hasher->verifyHashedPassword($test['hash'], $test['password']);
            $this->assertEquals($test['expected'], $test['actual']);


            $test['hash']       = $original['hash'].'+bogus';
            $test['password']   = $original['password'];
            $test['expected']   = 0;
            $test['actual']     = $hasher->verifyHashedPassword($test['hash'], $test['password']);
            $this->assertEquals($test['expected'], $test['actual']);

            $test['hash']       = $original['hash'];
            $test['password']   = $original['password'].'+bogus';
            $test['expected']   = 0;
            $test['actual']     = $hasher->verifyHashedPassword($test['hash'], $test['password']);
            $this->assertEquals($test['expected'], $test['actual']);
        }
    }
}
