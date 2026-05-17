<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Scalar\Int_;
use Rector\Rector\AbstractRector;

/**
 * Swaps the argument order of SFTP::chmod() from v3's (mode, path) to v4's (path, mode).
 *
 * phpseclib 3: $sftp->chmod(0777, 'file.txt')
 * phpseclib 4: $sftp->chmod('file.txt', 0777)
 *
 * Detection heuristic: any ->chmod() call whose first argument is an integer
 * literal. PHP's built-in chmod() is a function (not a method), so there is
 * no false-positive risk there; and no other common class exposes chmod(int, string).
 */
final class SFTPChmod extends AbstractRector
{
  public function getNodeTypes(): array
  {
    return [MethodCall::class];
  }

  public function refactor(Node $node): ?Node
  {
    if (!$node instanceof MethodCall) {
      return null;
    }

    if (!$this->isName($node->name, 'chmod')) {
      return null;
    }

    // Only act when the v3 signature is present: first arg is an int literal (octal mode)
    if (!isset($node->args[0], $node->args[1])) {
      return null;
    }

    if (!$node->args[0]->value instanceof Int_) {
      return null;
    }

    // Swap path and mode — args[2] (recursive flag) stays in place
    [$node->args[0], $node->args[1]] = [$node->args[1], $node->args[0]];

    return $node;
  }
}
