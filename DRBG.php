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
    
    public function __construct($test=FALSE, $testEntropy=NULL, $testNonce=NULL, $testPredictionResistanceFlag=FALSE, $testPersonalizationString=NULL) {
        $this->instantiate($test, $testEntropy, $testNonce, $testPredictionResistanceFlag, $testPersonalizationString);
    }
    
    public function __destruct() {
        $this->uninstantiate();
    }
    
    abstract protected function instantiateAlgorithm($entropy, $nonce, $personalizationString);
    
    abstract protected function reseedAlgorithm($entropy, $additionalInput);
    
    abstract protected function generateAlgorithm($requestedNumberOfBits, $additionalInput);
    
    abstract protected function uninstantiateAlgorithm();
    
    private function instantiate($test=FALSE, $testEntropy=NULL, $testNonce=NULL, $testPredictionResistanceFlag=FALSE, $testPersonalizationString='') {

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

	$predictResistanceFlag = $testPredictionResistanceFlag;
	$personalizationString = hex2bin($testPersonalizationString);

	if (strlen($personalizationString) * 8 > pow(2,35)) {
            throw new Exception('Personalization String exceeds maximum length.');
        }

        $this->instantiateAlgorithm($entropy, $nonce, $personalizationString);


    }
    
    private function uninstantiate() {
        $this->uninstantiateAlgorithm();
    	$this->reseedRequired = NULL;
    }

    public function reseed($additionalInput, $testEntropy=NULL) {
	try {
	    if (strlen($additionalInput) * 8 > pow(2,35)) {
	    	throw new Exception('Additional input exceeds maximum length');
	    }

	    if($testEntropy == NULL) {
	        $entropy = self::__getEntropyInput(self::STRENGTH);
	    } else {
		$entropy = hex2bin($testEntropy);
	    }

	    $this->reseedAlgorithm($entropy, $additionalInput);

	} catch (Exception $e) {
	    echo 'Caught exception: ', $e->getMessage(), "\n";
	}
    }
    
    public function generate($requestedNumberOfBits, $additionalInput=NULL, $predictionResistanceFlag=FALSE, $testEntropyPredictionResistence=NULL) {
        if ($requestedNumberOfBits > self::MAXBIT) {
            throw new Exception('Requested number of bits exceeds maximum supported.');
        }

	if (strlen($additionalInput) * 8 > pow(2,35)) {
            throw new Exception('Additional input exceeds maximum length.');
        }

	if ($predictionResistanceFlag == TRUE) {
	    $this->reseed($additionalInput, $testEntropyPredictionResistence);
	    $additionalInput = '';
	}

        $genOutput = $this->generateAlgorithm($requestedNumberOfBits, $additionalInput);
        
        if ($genOutput == 'Instantiation can no longer be used.') {
	    $this->reseed($additionalInput);
	    $additionalInput = '';
	    $genOutput = $this->generateAlgorithm($requestedNumberOfBits, $additionalInput);
	    //$this->uninstantiate();
            //throw new Exception($genOutput);
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

echo "Instantiate\n";
echo bin2hex($this->K) . "\n";
echo bin2hex($this->V) . "\n";
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
echo "Generate\n";
echo bin2hex($this->K) . "\n";
echo bin2hex($this->V) . "\n";
        return $genOutput;
    }

    protected function reseedAlgorithm($entropy, $additionalInput) {
    	$seed = $entropy . $additionalInput;
	$this->update($seed);
	$this->reseedCounter = 1;
echo "Reseed\n";
echo bin2hex($this->K) . "\n";
echo bin2hex($this->V) . "\n";
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

