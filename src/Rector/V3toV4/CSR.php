<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Arg;
use Rector\Rector\AbstractRector;

final class CSR extends AbstractRector
{
  public function getNodeTypes(): array
  {
    return [
      Expression::class,
      MethodCall::class,
    ];
  }

  public function refactor(Node $node): ?Node
  {
    // replace $csr = $x509->signCSR() with $privKey->sign($csr)
    if (
      $node instanceof Expression &&
      $node->expr instanceof Assign &&
      $node->expr->expr instanceof MethodCall &&
      $this->isName($node->expr->expr->name, 'signCSR')
      ) {
        return new Expression(new Methodcall(
          new Variable('privKey'), // TODO: currently privKey is hardcoded. change it so that this comes from setPrivateKey
          'sign',
          [new Arg($node->expr->var)]
        ));
    }

    // replace $x509->saveCSR($csr) with $csr->toString()
    if (
      $node instanceof MethodCall &&
      $this->isName($node->name, 'saveCSR')
      ) {
        return new Methodcall(
          $node->args[0]->value,
          new Identifier('toString')
        );
    }

    return null;
  }
}
