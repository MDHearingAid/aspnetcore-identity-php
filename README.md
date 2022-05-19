# aspnetcore-identity

[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Build Status][ico-travis]][link-travis]
[![Coverage Status][ico-scrutinizer]][link-scrutinizer]
[![Quality Score][ico-code-quality]][link-code-quality]
[![Total Downloads][ico-downloads]][link-downloads]

A direct PHP port of the algorithms used to generate and verify ASP.NET password hashes in .NET Core.

https://github.com/dotnet/aspnetcore/blob/master/src/Identity/Extensions.Core/src/PasswordHasher.cs

## Install

Via Composer

``` bash
$ composer require redrum0x/aspnetcore-identity
```

## Usage

``` php
$hasher = new MDHearing\AspNetCore\Identity\PasswordHasher();
$hashedPassword = $hasher->hashPassword('very strong password');
$result = $hasher->verifyHashedPassword($hashedPassword, 'very strong password');
```

## Change log

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Testing

``` bash
$ composer test
$ composer check-style
```

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) and [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) for details.

## Security

If you discover any security related issues, please email it@mdhearingaid.com instead of using the issue tracker.

## Credits

- [Steven Maguire][link-author]
- [All Contributors][link-contributors]

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.

[ico-version]: https://img.shields.io/packagist/v/mdhearing/aspnetcore-identity.svg?style=flat-square
[ico-license]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
[ico-travis]: https://img.shields.io/travis/MDHearingAid/aspnetcore-identity-php/master.svg?style=flat-square
[ico-scrutinizer]: https://img.shields.io/scrutinizer/coverage/g/MDHearingAid/aspnetcore-identity-php.svg?style=flat-square
[ico-code-quality]: https://img.shields.io/scrutinizer/g/MDHearingAid/aspnetcore-identity-php.svg?style=flat-square
[ico-downloads]: https://img.shields.io/packagist/dt/mdhearing/aspnetcore-identity.svg?style=flat-square

[link-packagist]: https://packagist.org/packages/mdhearing/aspnetcore-identity
[link-travis]: https://travis-ci.org/MDHearingAid/aspnetcore-identity-php
[link-scrutinizer]: https://scrutinizer-ci.com/g/MDHearingAid/aspnetcore-identity-php/code-structure
[link-code-quality]: https://scrutinizer-ci.com/g/MDHearingAid/aspnetcore-identity-php
[link-downloads]: https://packagist.org/packages/mdhearing/aspnetcore-identity
[link-author]: https://github.com/stevenmaguire
[link-contributors]: ../../contributors
