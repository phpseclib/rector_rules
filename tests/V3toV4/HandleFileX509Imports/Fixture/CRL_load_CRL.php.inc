<?php

use phpseclib3\File\X509;

final class SomeClass
{
  public function foo()
  {
    $x509 = new X509();
    $crl = $x509->loadCRL(file_get_contents('crl.bin'));
  }
}

?>
-----
<?php

use phpseclib4\File\CRL;

final class SomeClass
{
  public function foo()
  {
    $x509 = new X509();
    $crl = CRL::loadCRL(file_get_contents('crl.bin'));
  }
}

?>