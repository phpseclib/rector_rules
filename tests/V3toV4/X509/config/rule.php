<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use phpseclib\rectorRules\Rector\V3toV4\X509;
use phpseclib\rectorRules\Rector\V3toV4\HandleFileX509Imports;
use phpseclib\rectorRules\Rector\V3toV4\X509NodeVisitor;

return RectorConfig::configure()
  ->registerDecoratingNodeVisitor(X509NodeVisitor::class)
  ->withRules([HandleFileX509Imports::class])
  ->withRules([X509::class]);

