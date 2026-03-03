<?php

final class SomeClass
{
  public function foo()
  {
    $x509 = new \phpseclib3\File\X509();
    $x509->setPrivateKey($privKey);
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
    $spkac = CRL::loadCRL($privKey->getPublicKey());
  }
}
