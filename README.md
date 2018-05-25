# php-nist-800-90a [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
A NIST SP 800-90A Rev. 1-compliant session token generator for PHP applications

## Brief
This is an OO PHP implementation of NIST SP 800-90A Rev. 1 (Recommendation for Random Number Generation Using Deterministic Random Bit Generators). Please refer to https://csrc.nist.gov/Projects/Random-Bit-Generation/publications.

The DRBG defined here is currently based on SHA-256 HMAC and supports 256 bits strength with maximum output length 7500 bits.

Entropy input is obtained using OpenSSL and usage depends on the availability of a cryptographically strong algorithm locally.

## Usage

Use as defined in example.php:

```php
try {
    $drbg = new HMAC_DRBG();
    echo bin2hex($drbg->generate(1024)); // 1024 pseudorandom bits
} catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), "\n";
}
```

## Acknowledgements

Directory test contains NIST test vectors for DRBG implementations. Please refer to https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program.

Please note that even though this implementation passes NIST CAVP tests and is FIPS 140-compliant, it has not been submitted for official NIST validation.

## Authors

* Eduardo Vasconcelos (dudsan) - esmev@protonmail.ch
* Diogo Brandão (dbrandao) - dbrdem@hotmail.com

## License

This software is distributed under the [MIT License](https://github.com/dudsan/php-nist-800-90a/blob/master/LICENSE).

