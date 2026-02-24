<?php
use Rector\Config\RectorConfig;

use phpseclib\rectorRules\Rector\V3toV4\CSRAwareNodeVisitor;

use phpseclib\rectorRules\Rector\V3toV4\HandleFileX509Imports;
use phpseclib\rectorRules\Rector\V3toV4\X509;
use phpseclib\rectorRules\Rector\V3toV4\CSR;
use phpseclib\rectorRules\Rector\V3toV4\CRL;

return RectorConfig::configure()
  ->registerDecoratingNodeVisitor(CSRAwareNodeVisitor::class)
  ->withRules([
    HandleFileX509Imports::class, // first handle the imports
    X509::class,
    CSR::class,
    CRL::class,
  ])
  ->withPreparedSets(
    codingStyle: true,
  );
