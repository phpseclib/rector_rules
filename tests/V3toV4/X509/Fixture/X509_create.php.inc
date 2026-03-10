<?php

use phpseclib3\File\X509;

final class SomeClass
{
  public function foo()
  {
  $subject = new X509();
  $subject->setPublicKey($pubKey);
  $subject->setDN('/O=phpseclib demo subject');

  $issuer = new X509();
  $issuer->setPrivateKey($privKey);
  $issuer->setDN('/O=phpseclib demo issuer');

  $x509 = new X509();
  $result = $x509->sign($issuer, $subject);
  echo $x509->saveX509($result);
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
  $x509 = new X509($pubKey);
  $x509->setSubjectDN('/O=phpseclib demo subject');
  $x509->setIssuerDN('/O=phpseclib demo issuer');
  $privKey->sign($x509);
  echo $x509->toString();
  }
}

?>
