<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Arg;
use PhpParser\NodeTraverser;

use Rector\Rector\AbstractRector;

final class CSR extends AbstractRector
{
  private ?string $x509VarName = null;

  public function getNodeTypes(): array
  {
    return [
      Expression::class,
      MethodCall::class,
    ];
  }

  public function refactor(Node $node): null|Node|int
  {
    // remove unused $x509 = new X509() assignments
    if (
      $node instanceof Expression &&
      $node->expr instanceof Assign &&
      $node->expr->expr instanceof New_) {
        dump_node($node);
      if ($this->isName($node->expr->expr->class, 'phpseclib3\File\X509')) {

        $this->x509VarName = $node->expr->var->name;
        var_dump('');
        var_dump('#### this->varName ####');
        var_dump($this->varName);
        return NodeTraverser::REMOVE_NODE;
      }
      return null;
    }

    // replace $csr = $x509->signCSR() with $privKey->sign($csr)
    if (
      $node instanceof Expression &&
      $node->expr instanceof Assign &&
      $node->expr->expr instanceof MethodCall &&
      // $this->isName($node->expr->expr->var->name, $this->x509VarName) &&
      $this->isName($node->expr->expr->name, 'signCSR')
      ) {
        dump_node($node);
        return new Expression(new Methodcall(
          new Variable('privKey'), // TODO: currently privKey is hardcoded. change it so that this comes from setPrivateKey
          'sign',
          [new Arg($node->expr->var)]
        ));
    }

    // replace $x509->saveCSR($csr) with $csr->toString()
    if (
      $node instanceof MethodCall &&
      // $node->var->name === $this->x509VarName &&
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
