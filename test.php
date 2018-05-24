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
    $hmacDrbg = new HMAC_DRBG(TRUE, '4a8e0bd90bdb12f7748ad5f147b115d7385bb1b06aee7d8b76136a25d779bcb7', '7f3cce4af8c8ce3c45bdf23c6b181a00');
    
    $hmacDrbg->generate(1024);
    echo bin2hex($hmacDrbg->generate(1024)) . "\n";
    
    // Test HMAC_DRBG instance
    //testHmacDrbg($hmacDrbg, $testFileHome, $hmacTestFile);

} catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), "\n";
}

?>

