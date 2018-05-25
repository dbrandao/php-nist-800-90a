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
                $personalizationString = trim($personalizationString);
                $additionalInput0 = trim($additionalInput0);
                $additionalInput1 = trim($additionalInput1);
                $returnedBits = trim($returnedBits);
                
                // Test restricted to no PR, no personalization string, no additional input for now
                if ($predictionResistance == FALSE 
                    and $personalizationStringLen == 0 
                    and $additionalInputLen == 0) {

                    $countTest = $countTest + 1;
                    
                    $hmacDrbg = new HMAC_DRBG(TRUE, $entropyInput, $nonce);
                    $hmacDrbg->generate($returnedBitsLen);
                    if ($hmacDrbg->generate($returnedBitsLen) == hex2bin($returnedBits)) {
                        $countPass = $countPass + 1;
                    }
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

