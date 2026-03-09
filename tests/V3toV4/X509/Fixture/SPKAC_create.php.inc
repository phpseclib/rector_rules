<?php

use \phpseclib3\File\X509;

final class SomeClass
{
  public function foo()
  {
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
    $x509->setChallenge('123456789');
    $spkac = $x509->signSPKAC();
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
    $spkac->setChallenge('123456789');
    $privKey->sign($spkac);
  }
}

?>
