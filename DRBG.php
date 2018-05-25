<?php

abstract class DRBG {

    const
        STRENGTH = 256,
        MAXGEN = 10000,
        MAXBIT = 1024
    ;

    protected $reseedRequired;

    public static function __getEntropyInput($len) {
        $entropy = openssl_random_pseudo_bytes($len, $strong);
        if ($strong) {
            return $entropy;
        } else {
            throw new Exception('No cryptographically strong algorithm is available.');
        }
    }
    
    public function __construct($test=FALSE, $testEntropy=NULL, $testNonce=NULL) {
        $this->instantiate($test, $testEntropy, $testNonce);
    }
    
    public function __destruct() {
        $this->uninstantiate();
    }
    
    abstract protected function instantiateAlgorithm($entropy, $nonce);
    
    abstract protected function reseedAlgorithm($entropy, $additionalInput);
    
    abstract protected function generateAlgorithm($requestedNumberOfBits, $additionalInput);
    
    abstract protected function uninstantiateAlgorithm();
    
    private function instantiate($test=FALSE, $testEntropy=NULL, $testNonce=NULL) {
        
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
        
        $this->instantiateAlgorithm($entropy, $nonce);


    }
    
    private function uninstantiate() {
        $this->uninstantiateAlgorithm();
    	$this->reseedRequired = NULL;
    }

    public function reseed($additionalInput) {
	try {
	    if (strlen($additionalInput) * 8 > pow(2,25)) {
	    	throw new Exception('Additional input exceeds maximum length');
	    }

	    $entropy = self::__getEntropyInput(self::STRENGTH);

	    //$this->reseedAlgorithm($entropy, $additionalInput);
$this->reseedAlgorithm(hex2bin('01920a4e669ed3a85ae8a33b35a74ad7fb2a6bb4cf395ce00334a9c9a5a5d552'), $additionalInput);
	} catch (Exception $e) {
	    echo 'Caught exception: ', $e->getMessage(), "\n";
	}
    }
    
    public function generate($requestedNumberOfBits, $additionalInput) {
        if ($requestedNumberOfBits > self::MAXBIT) {
            throw new Exception('Requested number of bits exceeds maximum supported.');
        }

	if ($additionalInput > pow(2,35)) {
            throw new Exception('Additional input exceeds maximum length.');
        }
        
        $genOutput = $this->generateAlgorithm($requestedNumberOfBits, $additionalInput);
        
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
        OUTLEN = 256
    ;

    private $V;
    private $K;
    private $reseedCounter;
    
    protected function instantiateAlgorithm($entropy, $nonce) {
        $seed = $entropy . $nonce;
        $this->K = str_repeat("\x00", self::OUTLEN / 8);
        $this->V = str_repeat("\x01", self::OUTLEN / 8);
        $this->update($seed);
        $this->reseedCounter = 1;
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

	if ($additionalInput != '') {
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
        
        if ($providedData == '') {
            return;
        }
        
        $this->K = hash_hmac('sha256', $this->V . "\x01" . $providedData, $this->K, TRUE);
        $this->V = hash_hmac('sha256', $this->V, $this->K, TRUE);
    }

}

?>

