<?php

class DRBG {

    const
        ALGO_HMAC = 0,
        ALGO_HASH = 1,
        ALGO_CTR = 2
    ;
    
    private $algo;
    
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

