<?php

use phpseclib3\File\X509;
use phpseclib3\Crypt\Random;

class NamespaceSkipX509Class
{
    public function foo(): void
    {
        $x509 = new \phpseclib3\File\X509();
        $r = \phpseclib3\Crypt\Random::string(16);
    }
}

?>
-----
<?php

use phpseclib3\File\X509;
use phpseclib3\Crypt\Random;

class NamespaceSkipX509Class
{
    public function foo(): void
    {
        $x509 = new \phpseclib3\File\X509();
        $r = \phpseclib3\Crypt\Random::string(16);
    }
}

?>
