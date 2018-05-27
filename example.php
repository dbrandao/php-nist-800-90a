<?php

/**
 * Authors:
 * Eduardo Vasconcelos, esmev@protonmail.ch
 * Diogo Brandão, dbrdem@hotmail.com
 */

require_once 'DRBG.php';

// This file shows how to use DRBG.php, cycling through its various
// configurations.

// Maximum number of pseudorandom bits to generate (i.e.
// argument to generate()) is limited to 7500.

// Proper DRBG instantiations/calls to generate() are supposed
// to catch exceptions.

try {
    // Prediction resistance = False
    // Additional input = empty
    // Personalization string = empty
    $drbg = new HMAC_DRBG();
    $drbg->__destruct();
    
    // Prediction resistance = False
    // Additional input = empty
    // Personalization string = '63bc769ae1d95a98bde870e4db7776297041d37c8a5c688d4e024b78d83f4d78'
    $drbg = new HMAC_DRBG(FALSE, '63bc769ae1d95a98bde870e4db7776297041d37c8a5c688d4e024b78d83f4d78');
    $drbg->__destruct();
    
    // Prediction resistance = False
    // Additional input = '28848becd3f47696f124f4b14853a456156f69be583a7d4682cff8d44b39e1d3'
    // Personalization string = empty
    $drbg = new HMAC_DRBG();
    $drbg->__destruct();
    
    // Prediction resistance = False
    // Additional input = '28848becd3f47696f124f4b14853a456156f69be583a7d4682cff8d44b39e1d3'
    // Personalization string = '63bc769ae1d95a98bde870e4db7776297041d37c8a5c688d4e024b78d83f4d78'
    $drbg = new HMAC_DRBG(FALSE, '63bc769ae1d95a98bde870e4db7776297041d37c8a5c688d4e024b78d83f4d78');
    $drbg->__destruct();
    
    // Prediction resistance = True
    // Additional input = empty
    // Personalization string = empty
    $drbg = new HMAC_DRBG(TRUE);
    $drbg->__destruct();
    
    // Prediction resistance = True
    // Additional input = empty
    // Personalization string = '63bc769ae1d95a98bde870e4db7776297041d37c8a5c688d4e024b78d83f4d78'
    $drbg = new HMAC_DRBG(TRUE, '63bc769ae1d95a98bde870e4db7776297041d37c8a5c688d4e024b78d83f4d78');
    $drbg->__destruct();
    
    // Prediction resistance = True
    // Additional input = '28848becd3f47696f124f4b14853a456156f69be583a7d4682cff8d44b39e1d3'
    // Personalization string = empty
    $drbg = new HMAC_DRBG(TRUE);
    $drbg->__destruct();
    
    // Prediction resistance = True
    // Additional input = '28848becd3f47696f124f4b14853a456156f69be583a7d4682cff8d44b39e1d3'
    // Personalization string = '63bc769ae1d95a98bde870e4db7776297041d37c8a5c688d4e024b78d83f4d78'
    $drbg = new HMAC_DRBG(TRUE, '63bc769ae1d95a98bde870e4db7776297041d37c8a5c688d4e024b78d83f4d78');
    $drbg->__destruct();
    
    // Reseed
    // Additional input Reseed = empty
    $drbg = new HMAC_DRBG();
    $drbg->reseed();
    $drbg->__destruct();
    
    // Reseed
    // Additional input Reseed = '0e4dddbe0034180b59303d527a938a447bad9e4a91787d1072e6f41350ff11e5'
    $drbg = new HMAC_DRBG();
    $drbg->reseed('0e4dddbe0034180b59303d527a938a447bad9e4a91787d1072e6f41350ff11e5');
    $drbg->__destruct();
    
} catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), "\n";
}

?>

