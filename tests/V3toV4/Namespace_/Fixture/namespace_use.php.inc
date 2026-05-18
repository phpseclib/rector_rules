<?php

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\EC;
use phpseclib3\Net\SFTP;
use phpseclib3\Math\BigInteger;

class NamespaceUseClass
{
    public function foo(): void
    {
        $key = RSA::createKey();
        $ecKey = EC::createKey('nistp256');
        $sftp = new SFTP('example.com');
        $n = new BigInteger(42);
    }
}

?>
-----
<?php

use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\EC;
use phpseclib4\Net\SFTP;
use phpseclib4\Math\BigInteger;

class NamespaceUseClass
{
    public function foo(): void
    {
        $key = RSA::createKey();
        $ecKey = EC::createKey('nistp256');
        $sftp = new SFTP('example.com');
        $n = new BigInteger(42);
    }
}

?>
