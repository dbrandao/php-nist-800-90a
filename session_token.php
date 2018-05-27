<?php

/**
 * Authors:
 * Eduardo Vasconcelos, esmev@protonmail.ch
 * Diogo Brandão, dbrdem@hotmail.com
 */

require_once 'DRBG.php';

// This generates a NIST SP 800-90A Rev. 1-compliant
// hex-encoded 1024-bit session token using DRBG.php.

try {

    $drbg = new HMAC_DRBG();
    echo bin2hex( $drbg->generate(1024) );
    $drbg->__destruct();
    
} catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), "\n";
}

?>

