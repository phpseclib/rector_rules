<?php

use phpseclib3\File\X509;

final class SPKACSignClass
{
  public function foo()
  {
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
    $spkac = $x509->signSPKAC();
  }
}

?>
-----
<?php

use phpseclib4\File\SPKAC;

final class SPKACSignClass
{
  public function foo()
  {
    $spkac = new SPKAC($privKey->getPublicKey());
    $privKey->sign($spkac);
  }
}

?>
