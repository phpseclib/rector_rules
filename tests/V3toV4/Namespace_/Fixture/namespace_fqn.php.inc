<?php

class NamespaceFQNClass
{
    public function foo(): void
    {
        $sftp = new \phpseclib3\Net\SFTP('example.com');
        $n = new \phpseclib3\Math\BigInteger(42);
        $key = \phpseclib3\Crypt\RSA::createKey();
    }
}

?>
-----
<?php

class NamespaceFQNClass
{
    public function foo(): void
    {
        $sftp = new \phpseclib4\Net\SFTP('example.com');
        $n = new \phpseclib4\Math\BigInteger(42);
        $key = \phpseclib4\Crypt\RSA::createKey();
    }
}

?>
