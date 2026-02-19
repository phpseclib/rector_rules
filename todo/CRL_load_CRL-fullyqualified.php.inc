<?php

final class SomeClass
{
  function foo()
  {
    $x509 = new \phpseclib3\File\X509();
    $crl = $x509->loadCRL(file_get_contents('crl.bin'));
  }
}

?>
-----
<?php

use phpseclib4\File\CRL;
final class SomeClass
{
  function foo()
  {
    $x509 = new \phpseclib3\File\X509();
    $crl = CRL::loadCRL(file_get_contents('crl.bin'));
  }
}

?>
