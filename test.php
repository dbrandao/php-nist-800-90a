<?php

require_once 'DRBG.php';

function testDRBG($drbg, $testFileHome, $testFile) {

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
//$hashTestFile = 'HASH_DRBG.rsp';
//$ctrTestFile = 'CTR_DRBG.rsp';

// Test __getEntropy(...)
//$entropy = bin2hex(DRBG::__getEntropy(16));
//echo 'Entropy: 0x', $entropy, "\n"; // OK, it works.

// DRBG instances
try {
    // Test exception handling
    //$hmacDrbg = new DRBG(5); // OK, it works.
    
    // Instantiate DRBG objects
    $hmacDrbg = new DRBG(DRBG::ALGO_HMAC);
    //$hashDrbg = new DRBG(DRBG::ALGO_HASH);
    //$ctrDrbg = new DRBG(DRBG::ALGO_CTR);
    
    // Test DRBG instances
    testDRBG($hmacDrbg, $testFileHome, $hmacTestFile);
    //testDRBG($hashDrbg, $testFileHome, $hashTestFile);
    //testDRBG($ctrDrbg, $testFileHome, $ctrTestFile);

} catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), "\n";
}

?>

