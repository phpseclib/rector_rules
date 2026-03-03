<?php

use phpseclib3\File\X509;

final class SomeClass
{
  public function foo()
  {
    $x509 = new X509();
    $csr = $x509->loadCSR(file_get_contents('csr.csr'));
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
    $x509 = new X509();
    $csr = CSR::loadCSR(file_get_contents('csr.csr'));
  }
}

?>