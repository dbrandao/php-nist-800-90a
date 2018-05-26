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
    $hmacDrbg = new HMAC_DRBG(TRUE, '9969e54b4703ff31785b879a7e5c0eae0d3e309559e9fe96b0676d49d591ea4d', '07d20d46d064757d3023cac2376127ab', TRUE, '');
//$hmacDrbg->reseed(hex2bin('1ab4ca9014fa98a55938316de8ba5a68c629b0741bdd058c4d70c91cda5099b3'),'8ec6f7d5a8e2e88f43986f70b86e050d07c84b931bcf18e601c5a3eee3064c82');
    //$hmacDrbg->generate(1024, hex2bin('3f2fed4b68d506ecefa21f3f5bb907beb0f17dbc30f6ffbba5e5861408c53a1e'), FALSE);
    $hmacDrbg->generate(1024, '', TRUE, 'c60f2999100f738c10f74792676a3fc4a262d13721798046e29a295181569f54');
    echo "Returned bits: \n" . bin2hex($hmacDrbg->generate(1024, '', TRUE, 'c11d4524c9071bd3096015fcf7bc24a607f22fa065c937658a2a77a8699089f4')) . "\n";
    
    // Test HMAC_DRBG instance
    //testHmacDrbg($hmacDrbg, $testFileHome, $hmacTestFile);

} catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), "\n";
}

?>

