<?php

class CryptRandomFQNClass
{
    public function foo(): string
    {
        return \phpseclib3\Crypt\Random::string(16);
    }
}

?>
-----
<?php

class CryptRandomFQNClass
{
    public function foo(): string
    {
        return random_bytes(16);
    }
}

?>
