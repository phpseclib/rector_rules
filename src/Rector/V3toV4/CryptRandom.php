<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\UseItem;
use PhpParser\Node\Stmt\Use_;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\NodeTraverser;
use Rector\Rector\AbstractRector;

/**
 * Replaces phpseclib3\Crypt\Random::string($n) with random_bytes($n).
 *
 * phpseclib3\Crypt\Random existed because PHP 5.6 had no built-in CSPRNG.
 * PHP 7+ ships random_bytes(), which phpseclib 4 uses directly — the class
 * was removed entirely. Both the use-import and every call site are rewritten.
 *
 * Before:
 *   use phpseclib3\Crypt\Random;
 *   $bytes = Random::string(32);
 *
 * After:
 *   $bytes = random_bytes(32);
 */
final class CryptRandom extends AbstractRector
{
  public function getNodeTypes(): array
  {
    return [Use_::class, StaticCall::class];
  }

  public function refactor(Node $node): int|null|Node
  {
    if ($node instanceof Use_) {
      $node->uses = array_values(array_filter(
        $node->uses,
        fn(UseItem $item) => !$this->isName($item->name, 'phpseclib3\Crypt\Random')
      ));

      // Remove the Use_ statement entirely if it now has no items
      return count($node->uses) > 0 ? $node : NodeTraverser::REMOVE_NODE;
    }

    if (!$node instanceof StaticCall) {
      return null;
    }

    if (!$this->isNames($node->class, ['Random', 'phpseclib3\Crypt\Random'])) {
      return null;
    }

    if (!$this->isName($node->name, 'string')) {
      return null;
    }

    return new FuncCall(new Name('random_bytes'), $node->args);
  }
}
