<?php

abstract class DRBG {

    const
        MAX_SUPPORTED_STRENGTH = 256,
        MAX_PERSONALIZATION_STR_LEN = 256
    ;
    
    protected $strength;
    
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
    
    protected function instantiate($requestedStrength, $personalizationString) {
    
        try {
            if ($requestedStrength > self::MAX_SUPPORTED_STRENGTH) {
                throw new Exception('Requested strength exceeds maximum supported strength.');
            }
            
            // PR is always used

            if (strlen($personalizationString) * 8 > self::MAX_PERSONALIZATION_STR_LEN) {
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
            
            //TODO call to instantiateAlgorithm
            
        } catch (Exception $e) {
            echo 'Caught exception: ', $e->getMessage(), "\n";
        }
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
                "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
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

