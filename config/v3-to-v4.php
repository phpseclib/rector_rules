<?php
use Rector\Config\RectorConfig;

use phpseclib\rectorRules\Rector\V3toV4\CryptRandom;
use phpseclib\rectorRules\Rector\V3toV4\Namespace_;
use phpseclib\rectorRules\Rector\V3toV4\SFTPChmod;
use phpseclib\rectorRules\Rector\V3toV4\X509;

return RectorConfig::configure()
  ->withRules([
    Namespace_::class,
    CryptRandom::class,
    SFTPChmod::class,
    X509::class,
  ])
  ->withPreparedSets(
    codingStyle: true,
  );
