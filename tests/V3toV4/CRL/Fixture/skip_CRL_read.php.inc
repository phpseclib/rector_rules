<?php

use phpseclib4\File\CRL;

class ReadingCRLClass {
  public static function foo() {
    $crl = CRL::loadCRL(file_get_contents('crl.bin'));
  }
}
