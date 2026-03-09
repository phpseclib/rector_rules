<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;

use phpseclib\rectorRules\Rector\V3toV4\X509NodeVisitor;
use phpseclib\rectorRules\Rector\V3toV4\X509;

return RectorConfig::configure()
  ->registerDecoratingNodeVisitor(X509NodeVisitor::class)
  ->withRules([X509::class]);
