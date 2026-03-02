<?php

use phpseclib3\File\X509;

final class SomeClass
{
  public function foo()
  {
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
    // todo: handle
    $x509->setDNProp('id-at-organizationName', 'phpseclib demo cert');
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
    // todo: handle
    $x509->setDNProp('id-at-organizationName', 'phpseclib demo cert');
  }
}

?>
