<?php

require_once 'DRBG.php';

function testHmacDrbg($drbg, $testFileHome, $testFile) {

    if (substr($testFileHome, -1) != '/') {
        $testFileHome = $testFileHome . '/';
    }
    
    $handle = fopen($testFileHome . $testFile, 'rb');
    
    while ( ($line = fgets($handle, 4096)) !== false) {
        
        // TODO
    }
    
    if (!feof($handle)) {
        throw new Exception('Failed to parse test file.');
    }
}

// Test file home
$testFileHome = $argv[1];

// Test files
$hmacTestFile = 'HMAC_DRBG.rsp';

try {
    
    // Instantiate HMAC_DRBG object
    $hmacDrbg = new HMAC_DRBG(TRUE, '06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d', '0e66f71edc43e42a45ad3c6fc6cdc4df');
$hmacDrbg->reseed('');
    $hmacDrbg->generate(1024, '');

    echo bin2hex($hmacDrbg->generate(1024, '')) . "\n";
    
    // Test HMAC_DRBG instance
    //testHmacDrbg($hmacDrbg, $testFileHome, $hmacTestFile);

} catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), "\n";
}

?>

