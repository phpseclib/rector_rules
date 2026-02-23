<?php

use phpseclib3\File\X509;

final class SomeClass
{
  function foo()
  {
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
    $x509->setDNProp('id-at-organizationName', 'phpseclib demo cert');
  }
}

?>
-----
<?php

use phpseclib4\File\CSR;

final class SomeClass
{
  function foo()
  {
    $csr = new CSR($privKey->getPublicKey());
  }
}
