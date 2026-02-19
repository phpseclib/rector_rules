<?php

use \phpseclib3\File\X509;

final class SomeClass
{
  function foo()
  {
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
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
    $x509 = new X509();
    $spkac = CRL::loadCRL($privKey->getPublicKey());
  }
}
