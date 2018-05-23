<?php

class DRBG {

    const
        ALGO_HMAC = 0,
        ALGO_HASH = 1,
        ALGO_CTR = 2
    ;
    
    private $algo;
    
    public static function __getEntropy($len) {
        $entropy = openssl_random_pseudo_bytes($len, $strong);
        if ($strong) {
            return $entropy;
        } else {
            throw new Exception('No cryptographically strong algorithm is available.');
        }
    }
    
    public function __construct($algo) {
        if ($algo == self::ALGO_HMAC) {
            $this->algo = self::ALGO_HMAC;
        } else if ($algo == self::ALGO_HASH) {
            $this->algo = self::ALGO_HASH;
        } else if ($algo == self::ALGO_CTR) {
            $this->algo = self::ALGO_CTR;
        } else {
            throw new Exception('Invalid algorithm.');
        }
    }

}

?>

