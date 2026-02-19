<?php

final class SomeClass
{
  function foo()
  {
    $x509 = new \phpseclib3\File\X509();
    $cert = $x509->loadX509(file_get_contents('google.crt'));
  }
}

?>
-----
<?php

use phpseclib4\File\X509;

final class SomeClass
{
  function foo()
  {
    $x509 = new \phpseclib3\File\X509();
    $cert = X509::load(file_get_contents('google.crt'));
  }
}
