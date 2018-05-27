<?php

require_once 'DRBG.php';

const
    __NO_RESEED = 1,
    __PR_FALSE = 2,
    __PR_TRUE = 3,
    __HMAC_TEST_FILE = 'HMAC_DRBG.rsp'
    ;

function testHmacDrbg($testFileHome, $testFile, $__pr=__NO_RESEED) {

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
                if ($__pr == __PR_FALSE) {
                    fscanf($handle, "EntropyInputReseed = %s", $entropyInputReseed);
                    fscanf($handle, "AdditionalInputReseed = %s", $additionalInputReseed);
                }
                fscanf($handle, "AdditionalInput = %s", $additionalInput0);
                if ($__pr == __PR_TRUE) {
                    fscanf($handle, "EntropyInputPR = %s", $entropyInputPR0);
                }
                fscanf($handle, "AdditionalInput = %s", $additionalInput1);
                if ($__pr == __PR_TRUE) {
                    fscanf($handle, "EntropyInputPR = %s", $entropyInputPR1);
                }
                fscanf($handle, "ReturnedBits = %s", $returnedBits);
                
                $entropyInput = trim($entropyInput);
                $nonce = trim($nonce);
                if ($personalizationStringLen == 0) {
                    $personalizationString = NULL;
                } else {
                    $personalizationString = trim($personalizationString);
                }
                if ($__pr == __PR_FALSE) {
                    $entropyInputReseed = trim($entropyInputReseed);
                    $additionalInputReseed = trim($additionalInputReseed);
                }
                if ($additionalInputLen == 0) {
                    $additionalInput0 = NULL;
                    $additionalInput1 = NULL;
                    $additionalInputReseed = NULL;
                } else {
                    $additionalInput0 = trim($additionalInput0);
                    $additionalInput1 = trim($additionalInput1);
                }
                if ($__pr == __PR_TRUE) {
                    $entropyInputPR0 = trim($entropyInputPR0);
                    $entropyInputPR1 = trim($entropyInputPR1);                    
                } else {
                    $entropyInputPR0 = NULL;
                    $entropyInputPR1 = NULL;
                }
                $returnedBits = trim($returnedBits);
                
                $countTest = $countTest + 1;
                   
                $hmacDrbg = new HMAC_DRBG($predictionResistance, $personalizationString, TRUE, $entropyInput, $nonce);
                if ($__pr == __PR_FALSE) {
                    $hmacDrbg->reseed($additionalInputReseed, $entropyInputReseed);
                }
                $hmacDrbg->generate($returnedBitsLen, $additionalInput0, $predictionResistance, $entropyInputPR0);
                if ($hmacDrbg->generate($returnedBitsLen, $additionalInput1, $predictionResistance, $entropyInputPR1) == hex2bin($returnedBits)) {
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

// Test file homes
$testFileHomeNoReseed = $argv[1];
$testFileHomePrFalse = $argv[2];
$testFileHomePrTrue = $argv[3];

try {

    echo 'Testing w/ no_reseed: ';
    testHmacDrbg($testFileHomeNoReseed, __HMAC_TEST_FILE, __NO_RESEED); // _no_reseed
    
    echo 'Testing w/ pr_false: ';
    testHmacDrbg($testFileHomePrFalse, __HMAC_TEST_FILE, __PR_FALSE); // _pr_false
    
    echo 'Testing w/ pr_true: ';
    testHmacDrbg($testFileHomePrTrue, __HMAC_TEST_FILE, __PR_TRUE); // _pr_true

} catch (Exception $e) {
    
    echo 'Caught exception: ', $e->getMessage(), "\n";
}

?>

