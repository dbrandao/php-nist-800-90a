<?php

require_once 'DRBG.php';

// This will output a single NIST 800-90A Rev. 1-compliant
// pseudorandom 1024 bits token with 256 bits of strength
// (hex encoded).

// After 10k calls to generate() a 'Instantiation can no longer be used.'
// exception is thrown. When this happens a new DRBG object must be
// instantiated.

// Maximum number of pseudorandom bits to generate (i.e.
// argument to generate()) is limited to 7500.

// Proper DRBG instantiations/calls to generate() are supposed
// to catch exceptions.

try {
    $drbg = new HMAC_DRBG();
    echo bin2hex($drbg->generate(1024));
} catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), "\n";
}

?>
