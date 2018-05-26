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

    // Global
    $requestedNumberOfBits = 1024;

    // --------------------------------------------------------------------------------
    // Tests
    // --------------------------------------------------------------------------------
    //Instantiate Test
    $test = TRUE;
    $testEntropy = '';
    $testNonce = '';
    $testPersonalizationString = '';
    $testPredictionResistanceFlag = FALSE;

    //Reseed
    $testAdditionalInputReseed = hex2bin('');
    $EntropyInputReseed = '';

    //Generate (First Call)
    $testAdditionalInputGenerate1 = hex2bin('');
    $testEntropyInputPRGenrate1 = '';

    //Generate (Second Call)
    $testAdditionalInputGenerate2 = hex2bin('');
    $testEntropyInputPRGenrate2 = '';
    // --------------------------------------------------------------------------------
    // Instantiate HMAC_DRBG object
    $hmacDrbg = new HMAC_DRBG($test, $testEntropy, $testNonce, $testPredictionResistanceFlag, $testPersonalizationString);

    //$hmacDrbg->reseed($testAdditionalInputReseed,$EntropyInputReseed);
    
    $hmacDrbg->generate($requestedNumberOfBits, $testAdditionalInputGenerate1, $testPredictionResistanceFlag, $testEntropyInputPRGenrate1);

    echo "Returned bits: \n" . bin2hex($hmacDrbg->generate($requestedNumberOfBits, $testAdditionalInputGenerate2, $testPredictionResistanceFlag, $testEntropyInputPRGenrate2)) . "\n";
    
    // Test HMAC_DRBG instance
    //testHmacDrbg($hmacDrbg, $testFileHome, $hmacTestFile);

} catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), "\n";
}

?>

