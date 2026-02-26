<?php

use \phpseclib3\File\X509;

final class SomeClass
{
  public function foo()
  {
    $x509 = new X509();
    $cert = $x509->loadX509(file_get_contents('google.crt'));
  }
}

?>
-----
<?php

use phpseclib4\File\X509;

final class SomeClass
{
  public function foo()
  {
    $x509 = new X509();
    $cert = X509::load(file_get_contents('google.crt'));
  }
}

?>