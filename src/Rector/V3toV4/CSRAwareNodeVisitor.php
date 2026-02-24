<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\MethodCall;


use PhpParser\NodeVisitorAbstract;
use Rector\Contract\PhpParser\DecoratingNodeVisitorInterface;

final class CSRAwareNodeVisitor extends NodeVisitorAbstract implements DecoratingNodeVisitorInterface
{
  public const IS_CSR = 'is_csr';

  public function enterNode(Node $node)
  {
    if (!$node instanceof Class_) {
      return null;
    }
    $hasCsrMethodCall = false;

    foreach ($node->stmts as $stmt) {
      if (!$stmt instanceof ClassMethod) {
        continue;
      }

      foreach ($stmt->stmts ?? [] as $innerNnode) {
        if($innerNnode instanceof Expression && $innerNnode->expr instanceof MethodCall) {
          $methodName = $innerNnode->expr->name->name;
          if(in_array($methodName, ['setDNProp', 'signCSR', 'saveCSR'], true)) {
            $hasCsrMethodCall = true;
            break 2;
          }
        }
      }
    }

    // Set the attribute on the class itself
    // Todo: Set on each expression?
    if ($hasCsrMethodCall) {
      $node->setAttribute(self::IS_CSR, true);
    }
    return null;
  }
}
