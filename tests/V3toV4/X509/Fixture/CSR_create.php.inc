<?php

use phpseclib3\File\X509;

final class SomeClass
{
  public function foo()
  {
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
    $x509->setDNProp('id-at-organizationName', 'phpseclib demo cert');

    $csr = $x509->signCSR();
    echo $x509->saveCSR($csr);
  }
}

?>
-----
<?php

use phpseclib4\File\CSR;

final class SomeClass
{
  public function foo()
  {
    $csr = new CSR($privKey->getPublicKey());
    $csr->addDNProp('id-at-organizationName', 'phpseclib demo cert');

    $privKey->sign($csr);
    echo $csr->toString();
  }
}

?>
