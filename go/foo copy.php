<?php

use phpseclib3\File\X509;
use non\related\package;

class ReadCRLClass {
  public static function foo() {
    $x509 = new X509();
    $cert = $x509->loadCRL(file_get_contents('crl.bin'));
    // $cert = \phpseclib4\File\CRL::loadCRL(file_get_contents('crl.bin'));
  }
}

class LoadSpkacClass {
  public static function foo() {
    $x509 = new X509();
    $spkac = $x509->loadSPKAC(file_get_contents('spkac.txt'));
    // $spkac = \phpseclib4\File\CRL::loadCRL(file_get_contents('spkac.txt'));
  }
}

class createCSRClass {
  public static function foo() {
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
    // $csr = new \phpseclib4\File\CSR($privKey->getPublicKey());
    $x509->setDNProp('id-at-organizationName', 'phpseclib demo cert');

    $csr = $x509->signCSR();

    echo $x509->saveCSR($csr);
  }
}


class CreateSpkacClass {
  public static function foo() {
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
    $x509->setChallenge('123456789');
    $spkac = $x509->signSPKAC();
    // $spkac = new \phpseclib4\File\CRL::loadCRL($privKey->getPublicKey());
    // $spkac->setChallenge('123456789');
    // $privKey->sign($spkac);
  }
}


class CreateSpkacClass {
  public static function foo() {
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
    $x509->setChallenge('123456789');
  }
}
class createCSRClass {
  public static function foo() {
    $x509 = new X509();
    $x509->setPrivateKey($privKey);
    // $csr = new \phpseclib4\File\CSR($privKey->getPublicKey());
    $x509->setDNProp('id-at-organizationName', 'phpseclib demo cert');
  }
}
// class ResultCreateSpkacClass {
//   use phpseclib4\File\CRL;

//   private $privKey = 'test';

//   public static function foo() {
//     // $spkac = new CRL::loadCRL($privKey->getPublicKey());
//     $spkac = new \phpseclib4\File\CRL::loadCRL($privKey->getPublicKey());
//     $spkac->setChallenge('123456789');
//     $privKey->sign($spkac);
//   }
// }

?>
