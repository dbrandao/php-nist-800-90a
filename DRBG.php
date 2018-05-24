<?php

abstract class DRBG {

    const
        STRENGTH = 256,
        MAX_BITS = 1024
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
            $entropy = hex2bin('79737479ba4e7642a221fcfd1b820b134e9e3540a35bb48ffae29c20f5418ea3');//self::__getEntropyInput(self::STRENGTH);
            $nonce = hex2bin('3593259c092bef4129bc2c6c9e19f343');//self::__getEntropyInput(self::STRENGTH / 2);
            $this->instantiateAlgorithm($entropy, $nonce);
        } catch (Exception $e) {
            echo 'Caught exception: ' . $e->getMessage();
        }
    }
    
    private function uninstantiate() {
        $this->uninstantiateAlgorithm();
    }
    
    public function generate($requestedNumberOfBits) {
        if ($requestedNumberOfBits > self::MAX_BITS) {
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

    const                 
        MAX_GEN = 10000
    ;

    private $V;
    private $K;
    private $reseedCounter;
    
    protected function instantiateAlgorithm($entropy, $nonce) {
        $seed = $entropy . $nonce;
        $this->K = str_repeat("\x00", 256 / 8);
        $this->V = str_repeat("\x01", 256 / 8);
        $this->update($seed);
        $this->reseedCounter = 1;
    }
    
    protected function uninstantiateAlgorithm() {
        $this->V = NULL;
        $this->K = NULL;
        $this->reseedCounter = NULL;
    }
    
    protected function generateAlgorithm($requestedNumberOfBits) {
        if ($this->reseedCounter > self::MAX_GEN) {
            return 'Instantiation can no longer be used.';
        }
        
        $temp = '';
        
        while (strlen($temp) < $requestedNumberOfBits / 8) {
            $this->V = hash_hmac('sha256', $this->V, $this->K, TRUE);
            $temp = $temp . $this->V;
        }
        
        $genOutput = substr($temp, 0, ($requestedNumberOfBits / 8));
        
        $this->update('');
        echo '#' . bin2hex($this->V) . "#\n";
        echo '#' . bin2hex($this->K) . "#\n";
        
        $this->reseedCounter = $this->reseedCounter + 1;
        
        return $genOutput;
    }
    
    private function update($providedData) {
        $this->K = hash_hmac('sha256', $this->V . "\x00" . $providedData, $this->K, TRUE);
        $this->V = hash_hmac('sha256', $this->V, $this->K, TRUE);
        
        if ($providedData == '') {
            return;
        }
        
        $this->K = hash_hmac('sha256', $this->V . "\x01" . $providedData, $this->K, TRUE);
        $this->V = hash_hmac('sha256', $this->V, $this->K, TRUE);
    }

}

?>

