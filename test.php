<?php

require_once 'DRBG.php';

function testHmacDrbg($drbg, $testFileHome, $testFile) {

    if (substr($testFileHome, -1) != '/') {
        $testFileHome = $testFileHome . '/';
    }
    
    // Debug
    //echo 'Test file is at: ', $testFileHome . $testFile, "\n";
    
    $handle = fopen($testFileHome . $testFile, 'rb');
    
    while ( ($line = fgets($handle, 4096)) !== false) {
        
        // Debug
        // echo $line; // OK, it works.
    }
    
    if (!feof($handle)) {
        throw new Exception('Failed to parse test file.');
    }
}

// Test file home
$testFileHome = $argv[1];

// Test files
$hmacTestFile = 'HMAC_DRBG.rsp';

// Test __getEntropyInput
//$entropy = bin2hex(DRBG::__getEntropyInput(16));
//echo 'Entropy: ', $entropy, "\n"; // OK, it works.

// DRBG instantiation
try {
    // Test exception handling
    //$hmacDrbg = new HMAC_DRBG(1024, ''); // OK, it works.
    
    // Instantiate HMAC_DRBG object
    $hmacDrbg = new HMAC_DRBG();
    
    //
    echo bin2hex($hmacDrbg->generate(1024)) . "\n\n";
    echo bin2hex($hmacDrbg->generate(1024)) . "\n";
    
    // Test HMAC_DRBG instance
    //testHmacDrbg($hmacDrbg, $testFileHome, $hmacTestFile);

} catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), "\n";
}

?>

