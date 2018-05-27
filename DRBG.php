<?php

abstract class DRBG {

    const
        STRENGTH = 256,
        MAXGEN = 10000,
        MAXBIT = 7500,
        MAXPSTR = 256,
        MAXAINPUT = 256
    ;
    
    public static function __getEntropyInput($len) {
        $entropy = openssl_random_pseudo_bytes($len, $strong);
        if ($strong) {
            return $entropy;
        } else {
            throw new Exception('No cryptographically strong algorithm is available.');
        }
    }
    
    public function __construct($predictionResistanceFlag=TRUE, $personalizationString=NULL, $test=FALSE, $testEntropy=NULL, $testNonce=NULL) {
        $this->instantiate($predictionResistanceFlag, $personalizationString, $test, $testEntropy, $testNonce);
    }
    
    public function __destruct() {
        $this->uninstantiate();
    }
    
    abstract protected function instantiateAlgorithm($entropy, $nonce, $personalizationString);
    
    abstract protected function reseedAlgorithm($entropy, $additionalInput);
    
    abstract protected function generateAlgorithm($requestedNumberOfBits, $additionalInput);
    
    abstract protected function uninstantiateAlgorithm();
    
    private function instantiate($predictionResistanceFlag, $personalizationString, $test, $testEntropy, $testNonce) {
        
        if (!$test) {
        
            $entropy = self::__getEntropyInput(self::STRENGTH);
            $nonce = self::__getEntropyInput(self::STRENGTH / 2);
            
        } else {
        
            if ($testEntropy == NULL or $testNonce == NULL) {
                throw new Exception('Need entropy and nonce for test.');
            }
            
            $entropy = hex2bin($testEntropy);
            $nonce = hex2bin($testNonce);
        }
        
        if (strlen($personalizationString) * 4 > self::MAXPSTR) {
            throw new Exception('Personalization string exceeds maximum length.');
        }
        
        $this->instantiateAlgorithm($entropy, $nonce, hex2bin($personalizationString));
    }
    
    private function uninstantiate() {
        $this->uninstantiateAlgorithm();
    }
    
    public function reseed($additionalInput, $testEntropy=NULL) {
        
        if (strlen($additionalInput) * 4 > self::MAXAINPUT) {
            throw new Exception('Additional input exceeds maximum length');
        }
        
        if($testEntropy == NULL) {
            $entropy = self::__getEntropyInput(self::STRENGTH);
        } else {
            $entropy = hex2bin($testEntropy);
        }
        
        $this->reseedAlgorithm($entropy, hex2bin($additionalInput));
    }
    
    public function generate($requestedNumberOfBits, $additionalInput=NULL, $predictionResistanceFlag=FALSE, $testEntropyPredictionResistance=NULL) {
        if ($requestedNumberOfBits > self::MAXBIT) {
            throw new Exception('Requested number of bits exceeds maximum supported.');
        }
        
        if (strlen($additionalInput) * 4 > self::MAXAINPUT) {
            throw new Exception('Additional input exceeds maximum length');
        }
        
        if ($predictionResistanceFlag == TRUE) {
            $this->reseed($additionalInput, $testEntropyPredictionResistance);
            $additionalInput = NULL;
        }
        
        $genOutput = $this->generateAlgorithm($requestedNumberOfBits, hex2bin($additionalInput));
        
        if ($genOutput == 'Instantiation can no longer be used.') {
            $this->reseed($additionalInput);
            $additionalInput = NULL;
            $genOutput = $this->generateAlgorithm($requestedNumberOfBits, $additionalInput);
        }
        
        return $genOutput;
    }
}

class HMAC_DRBG extends DRBG {

    const
        OUTLEN = 256
    ;

    private $V;
    private $K;
    private $reseedCounter;
    
    protected function instantiateAlgorithm($entropy, $nonce, $personalizationString) {
        $seed = $entropy . $nonce . $personalizationString;
        $this->K = str_repeat("\x00", self::OUTLEN / 8);
        $this->V = str_repeat("\x01", self::OUTLEN / 8);
        $this->update($seed);
        $this->reseedCounter = 1;
        
//        echo bin2hex($this->V) . "\n";
//        echo bin2hex($this->K) . "\n\n";
        
    }
    
    protected function uninstantiateAlgorithm() {
        $this->V = NULL;
        $this->K = NULL;
        $this->reseedCounter = NULL;
    }
    
    protected function generateAlgorithm($requestedNumberOfBits, $additionalInput) {
        if ($this->reseedCounter > self::MAXGEN) {
            return 'Instantiation can no longer be used.';
        }
        
        if ($additionalInput != NULL) {
            $this->update($additionalInput);
        }
        
        $temp = '';
        
        while (strlen($temp) < $requestedNumberOfBits / 8) {
            $this->V = hash_hmac('sha256', $this->V, $this->K, TRUE);
            $temp = $temp . $this->V;
        }
        
        $genOutput = substr($temp, 0, ($requestedNumberOfBits / 8));
        
        $this->update($additionalInput);
        
        $this->reseedCounter = $this->reseedCounter + 1;
        
//        echo bin2hex($this->V) . "\n";
//        echo bin2hex($this->K) . "\n\n";
        
        return $genOutput;
    }
    
    protected function reseedAlgorithm($entropy, $additionalInput) {
        $seed = $entropy . $additionalInput;
        $this->update($seed);
        $this->reseedCounter = 1;
    }
    
    private function update($providedData) {
        $this->K = hash_hmac('sha256', $this->V . "\x00" . $providedData, $this->K, TRUE);
        $this->V = hash_hmac('sha256', $this->V, $this->K, TRUE);
        
        if ($providedData == NULL) {
            return;
        }
        
        $this->K = hash_hmac('sha256', $this->V . "\x01" . $providedData, $this->K, TRUE);
        $this->V = hash_hmac('sha256', $this->V, $this->K, TRUE);
    }

}

?>

