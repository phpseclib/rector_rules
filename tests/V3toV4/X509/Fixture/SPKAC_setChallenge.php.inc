<?php
use phpseclib3\File\X509;

final class SPKACSetChallenge
{
  public function foo()
  {
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
    $x509->setChallenge('123456789');
  }
}

?>
-----
<?php
use phpseclib4\File\CRL;

final class SPKACSetChallenge
{
  public function foo()
  {
    $spkac = CRL::loadCRL($privKey->getPublicKey());
    $spkac->setChallenge('123456789');
  }
}

?>
