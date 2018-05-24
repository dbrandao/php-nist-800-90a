<?php

abstract class DRBG {

    const
        STRENGTH = 256, // This implementation uses 256 bits strength
        OUT_BLK_LEN = 512, // Output block length for SHA-512
        MAX_GEN_BITS = 7500, // At most 7500 bit strings per call to generate
        RESEED_INTERVAL = 20000 // At most 20k calls to generate before reseed
    ;
    
    public static function __getEntropyInput($len) {
        $entropy = openssl_random_pseudo_bytes($len, $strong);
        if ($strong) {
            return $entropy;
        } else {
            throw new Exception('No cryptographically strong algorithm is available.');
        }
    }
    
    public function __construct() {
        $this->instantiate();
    }
    
    public function __destruct() {
        $this->uninstantiate();
    }
    
    abstract protected function instantiateAlgorithm($entropy, $nonce);
    
    abstract protected function generateAlgorithm($requestedNumberOfBits);
    
    abstract protected function uninstantiateAlgorithm();
    
    private function instantiate() {
        
        try {    
            $entropy = self::__getEntropyInput((int) 1.5 * self::STRENGTH);
            $nonce = self::__getEntropyInput(self::STRENGTH / 2);
            $this->instantiateAlgorithm($entropy, $nonce);
        } catch (Exception $e) {
            echo 'Caught exception: ' . $e->getMessage();
        }
    }
    
    private function uninstantiate() {
        $this->uninstantiateAlgorithm();
    }
    
    public function generate($requestedNumberOfBits) {
        if ($requestedNumberOfBits > self::MAX_GEN_BITS) {
            throw new Exception('Requested number of bits exceeds maximum supported.');
        }
        
        $genOutput = $this->generateAlgorithm($requestedNumberOfBits);
        
        if ($genOutput == 'Instantiation can no longer be used.') {
            $this->uninstantiate();
            throw new Exception($genOutput);
        } else {
            return $genOutput;
        }
        
    }

}

class HMAC_DRBG extends DRBG {

    private $V;
    private $K;
    private $reseedCounter;
    
    protected function instantiateAlgorithm($entropy, $nonce) {
        $seed = $entropy . $nonce;
        $this->K = str_repeat("\x00", self::OUT_BLK_LEN / 8);
        $this->V = str_repeat("\x01", self::OUT_BLK_LEN / 8);
        $this->update($seed);
        $this->reseedCounter = 1;
    }
    
    protected function uninstantiateAlgorithm() {
        $this->V = NULL;
        $this->K = NULL;
        $this->reseedCounter = NULL;
    }
    
    protected function generateAlgorithm($requestedNumberOfBits) {
        if ($this->reseedCounter > self::RESEED_INTERVAL) {
            return 'Instantiation can no longer be used.';
        }
        
        $temp = '';
        
        while (strlen($temp) < $requestedNumberOfBits / 8) {
            $this->V = hash_hmac('sha512', $this->V, $this->K, TRUE);
            $temp = $temp . $this->V;
        }
        
        $genOutput = substr($temp, 0, ($requestedNumberOfBits / 8));
        
        $this->update('');
        
        $this->reseedCounter = $this->reseedCounter + 1;
        
        return $genOutput;
    }
    
    private function update($providedData) {
        $this->K = hash_hmac('sha512', $this->V . "\x00" . $providedData, $this->K, TRUE);
        $this->V = hash_hmac('sha512', $this->V, $this->K, TRUE);
        
        if ($providedData == '') {
            return;
        }
        
        $this->K = hash_hmac('sha512', $this->V . "\x01" . $providedData, $this->K, TRUE);
        $this->V = hash_hmac('sha512', $this->V, $this->K, TRUE);
    }

}

?>

