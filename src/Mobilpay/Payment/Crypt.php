<?php

namespace Mobilpay\Payment;

/**
 * Class Crypt
 *
 * Symmetric crypto helpers for the NETOPIA envelope. Lives under the
 * Mobilpay\Payment\ namespace so it is covered by the package PSR-4 autoload.
 */
class Crypt
{
    /**
     * Pure-PHP RC4 (symmetric). Replaces the RC4 leg of openssl_open()/openssl_seal(),
     * which is unavailable on OpenSSL 3 without the legacy provider. Encrypt == decrypt.
     *
     * @param string $key
     * @param string $data
     *
     * @return string
     */
    public static function rc4($key, $data)
    {
        $s = range(0, 255);
        $j = 0;
        $keyLen = strlen($key);
        for ($i = 0; $i < 256; $i++) {
            $j = ($j + $s[$i] + ord($key[$i % $keyLen])) & 255;
            $tmp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $tmp;
        }
        $i = $j = 0;
        $out = '';
        for ($y = 0, $len = strlen($data); $y < $len; $y++) {
            $i = ($i + 1) & 255;
            $j = ($j + $s[$i]) & 255;
            $tmp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $tmp;
            $out .= $data[$y] ^ chr($s[($s[$i] + $s[$j]) & 255]);
        }

        return $out;
    }
}
