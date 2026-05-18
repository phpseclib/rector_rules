<?php

final class SomeClass
{
  public function foo()
  {
    $x509 = new \phpseclib3\File\X509();
    $x509->setPrivateKey($privKey);
    $x509->setChallenge('123456789');
    $spkac = $x509->signSPKAC();
  }
}

?>
-----
<?php

use phpseclib4\File\SPKAC;
final class SomeClass
{
  public function foo()
  {
    $spkac = new SPKAC($privKey->getPublicKey());
    $spkac->setChallenge('123456789');
    $privKey->sign($spkac);
  }
}
