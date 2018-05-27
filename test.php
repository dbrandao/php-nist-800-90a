<?php

require_once 'DRBG.php';

function testHmacDrbg($testFileHome, $testFile) {

    if (substr($testFileHome, -1) != '/') {
        $testFileHome = $testFileHome . '/';
    }
    
    $handle = fopen($testFileHome . $testFile, 'rb');
    
    $countTest = 0;
    $countPass = 0;
    
    while (fscanf($handle, "%s", $line)) {
        if ($line == '[SHA-256]') {
        
            // Read SHA-256 DRBG parameters
            fscanf($handle, "[PredictionResistance = %s]", $predictionResistance);
            fscanf($handle, "[EntropyInputLen = %d]", $entropyInputLen);
            fscanf($handle, "[NonceLen = %d]", $nonceLen);
            fscanf($handle, "[PersonalizationStringLen = %d]", $personalizationStringLen);
            fscanf($handle, "[AdditionalInputLen = %d]", $additionalInputLen);
            fscanf($handle, "[ReturnedBitsLen = %d]", $returnedBitsLen);
            $predictionResistance = !(trim(explode(']', $predictionResistance)[0]) == 'False');
            
            // Read DRBG test vectors 0-14
            for ($i = 0; $i < 15; $i++) {

                fscanf($handle, "%s");
                fscanf($handle, "COUNT = %d", $count);
                fscanf($handle, "EntropyInput = %s", $entropyInput);
                fscanf($handle, "Nonce = %s", $nonce);
                fscanf($handle, "PersonalizationString = %s", $personalizationString);
                fscanf($handle, "AdditionalInput = %s", $additionalInput0);
                fscanf($handle, "AdditionalInput = %s", $additionalInput1);
                fscanf($handle, "ReturnedBits = %s", $returnedBits);
                
                $entropyInput = trim($entropyInput);
                $nonce = trim($nonce);
                if ($personalizationStringLen == 0) {
                    $personalizationString = NULL;
                } else {
                    $personalizationString = trim($personalizationString);
                }
                if ($additionalInputLen == 0) {
                    $additionalInput0 = NULL;
                    $additionalInput1 = NULL;
                } else {
                    $additionalInput0 = trim($additionalInput0);
                    $additionalInput1 = trim($additionalInput1);
                }
                $returnedBits = trim($returnedBits);
                
                $countTest = $countTest + 1;
                   
                $hmacDrbg = new HMAC_DRBG($predictionResistance, $personalizationString, TRUE, $entropyInput, $nonce);
                $hmacDrbg->generate($returnedBitsLen, $additionalInput0, $predictionResistance);
                if ($hmacDrbg->generate($returnedBitsLen, $additionalInput1, $predictionResistance) == hex2bin($returnedBits)) {
                    $countPass = $countPass + 1;
                } else {
                    echo 'Test #' . $countTest . ' expected: ' . $returnedBits . "\n\n";
                    throw new Exception('Failed test.'); 
                }
            }
            
            fscanf($handle, "%s");
            
        }        
    }
    
    echo 'Passed ' . $countPass . '/' . $countTest . " test vectors.\n";
    
    if (!feof($handle)) {
        throw new Exception('Failed to parse test file.');
    }
}

// Test file home
$testFileHome = $argv[1];

// Test files
$hmacTestFile = 'HMAC_DRBG.rsp';

try {

    testHmacDrbg($testFileHome, $hmacTestFile);

} catch (Exception $e) {
    
    echo 'Caught exception: ', $e->getMessage(), "\n";
}

?>

