<?php

use phpseclib3\File\X509;
use non\related\package;

final class createCSRClass {
  public function foo() {
    // $csr = new \phpseclib4\File\CSR($privKey->getPublicKey());
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
    $x509->setDNProp('id-at-organizationName', 'phpseclib demo cert');
  }
}

// class CreateSpkacClass {
//   public static function foo() {
//     $x509 = new X509();
//     $x509->setPrivateKey($privKey);
//     $x509->setChallenge('123456789');
//     // $spkac = new \phpseclib4\File\CRL::loadCRL($privKey->getPublicKey());
//   }
// }


?>
