<?php

use phpseclib3\File\X509;

class ReadCRLClass {
  public static function foo() {
    $x509 = new X509();
    $crl = $x509->loadCRL(file_get_contents('crl.bin'));
  }
}

?>
-----
<?php

use phpseclib4\File\CRL;
class ReadCRLClass {
  public static function foo() {
    $crl = CRL::loadCRL(file_get_contents('crl.bin'));
  }
}

?>
