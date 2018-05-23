<?php

abstract class DRBG {

    const
        MAX_SUPPORTED_STRENGTH = 256,
        MAX_2_BASE = 2,
        MAX_35_EXP = 35,
        MAX_19_EXP = 19
    ;
    
    protected $strength;
    protected $reseedRequired;
    
    public static function __getEntropyInput($len) {
        $entropy = openssl_random_pseudo_bytes($len, $strong);
        if ($strong) {
            return $entropy;
        } else {
            throw new Exception('No cryptographically strong algorithm is available.');
        }
    }
    
    public function __construct($requestedStrength, $personalizationString) {
        $this->instantiate($requestedStrength, $personalizationString);
    }
    
    abstract protected function instantiateAlgorithm($entropy, $nonce, $personalizationString, $strength);
    
    abstract protected function reseedAlgorithm($entropy, $additionalInput);
    
    abstract protected function generateAlgorithm($requestedNumberOfBits, $additionalInput, &$reseedRequired);
    
    abstract protected function uninstantiateAlgorithm();
    
    private function instantiate($requestedStrength, $personalizationString) {
    
        try {
            if ($requestedStrength > self::MAX_SUPPORTED_STRENGTH) {
                throw new Exception('Requested strength exceeds maximum supported strength.');
            }
            
            // PR is always used

            if (strlen($personalizationString) * 8 > pow(self::MAX_2_BASE, self::MAX_35_EXP)) {
                throw new Exception('Personalization string exceeds maximum length.');
            }
            
            if ($requestedStrength <= 112) {
                $this->strength = 112;
            } else if ($requestedStrength <= 128) {
                $this->strength = 128;
            } else if ($requestedStrength <= 192) {
                $this->strength = 192;
            } else {
                $this->strength = 256;
            }
            
            $entropy = self::__getEntropyInput($this->strength);

            $nonce = self::__getEntropyInput($this->strength / 2);
            
            $this->instantiateAlgorithm($entropy, $nonce, $personalizationString, $this->strength);
            
        } catch (Exception $e) {
            echo 'Caught exception: ', $e->getMessage(), "\n";
        }
    }
    
    private function uninstantiate() {
        $this->strength = NULL;
        $this->reseedRequired = NULL;
    }
    
    public function reseed($additionalInput) {

        try {
        
            if (strlen($additionalInput) * 8 > pow(self::MAX_2_BASE, self::MAX_35_EXP)) {
                throw new Exception('Addidional input exceeds maximum length.');
            }
            
            $entropy = self::__getEntropyInput($this->strength);
            
            $this->reseedAlgorithm($entropy, $additionalInput);
            
        } catch (Exception $e) {
            echo 'Caught exception: ', $e->getMessage(), "\n";
        }
    }
    
    public function generate($requestedNumberOfBits, $strength, $additionalInput) {
        if ($requestedNumberOfBits > pow(self::MAX_2_BASE, self::MAX_19_EXP)) {
            throw new Exception('Requested number of bits exceeds maximum supported.');
        }
        
        if ($requestedNumberOfBits > $this->strength) {
            throw new Exception('Requested strength exceeds instance strength.');
        }
        
        if (strlen($additionalInput) * 8 > pow(self::MAX_2_BASE, self::MAX_35_EXP)) {
            throw new Exception('Addidional input exceeds maximum length.');
        }
        
        $output = generateAlgorithm($requestedNumberOfBits, $additionalInput, $reseedRequired);
        
        if ($reseedRequired) {
            $this->uninstantiate();
            $this->uninstantiateAlgorithm();
        }
        
        return $output;
        
    }

}

class HMAC_DRBG extends DRBG {

    const
        INIT_V = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    
        INIT_K = "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" .
                "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" .
                "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" .
                "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
                
        MAX_GEN_BEFORE_RESEED = 10000,
        RESEED_REQUIRED = NULL
    ;

    private $V; // secret, output
    private $K; // secret, key
    private $reseedCounter;
    
    protected function instantiateAlgorithm($entropy, $nonce, $personalizationString, $strength) {
        $seed = $entropy . $nonce . $personalizationString;
        $this->K = self::INIT_K;
        $this->V = self::INIT_V;
        $this->update($seed);
        $this->reseedCounter = 1;
    }
    
    protected function uninstantiateAlgorithm() {
        $this->V = NULL;
        $this->K = NULL;
        $this->reseedCounter = NULL;
    }
    
    protected function generateAlgorithm($requestedNumberOfBits, $additionalInput, &$reseedRequired) {
        if ($reseedCounter > self::MAX_GEN_BEFORE_RESEED) {
            $reseedRequired = true;
            return self::RESEED_REQUIRED;
        }
        
        if ($additionalInput != '') {
            $this->update(additionalInput);
        }
        
        $temp = '';
        
        while (strlen($temp) < $requestedNumberOfBits / 8) {
            $this->V = hash_hmac('sha256', $this->V, $this->K);
            $temp = $temp . $this->V;
        }
        
        $output = substr($temp, 0, $requestedNumberOfBits / 8);
        
        $this->update($additionalInput);
        
        $this->reseedCounter = $this->reseedCounter + 1;
        
        return $output;
    }
    
    protected function reseedAlgorithm($entropy, $additionalInput) {
        $seed = $entropy . $additionalInput;
        $this->K = $this->update($seed);
        $reseedCounter = 1;
    }
    
    private function update($providedData) {
        $this->K = hash_hmac('sha256', $this->V . 0x00 . $providedData, $this->K);
        $this->V = hash_hmac('sha256', $this->V, $this->K);
        
        if ($providedData == '') {
            return;
        }
        
        $this->K = hash_hmac('sha256', $this->V . 0x01 . $providedData, $this->K);
        $this->V = hash_hmac('sha256', $this->V, $this->K);
    }

}

?>

