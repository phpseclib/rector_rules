<?php

final class SomeClass
{
  function foo()
  {
    $x509 = new \phpseclib3\File\X509();
    $spkac = $x509->loadSPKAC(file_get_contents('spkac.txt'));
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
    $spkac = CRL::loadCRL(file_get_contents('spkac.txt'));
  }
}

?>
