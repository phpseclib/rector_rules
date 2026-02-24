<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use Rector\Rector\AbstractRector;

use PhpParser\NodeTraverser;
use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Name\FullyQualified;
use PhpParser\Node\Identifier;

use PhpParser\Node\Stmt\Nop;
use PhpParser\Node\Stmt\Use_;
use PhpParser\Node\Stmt\UseUse;
use PhpParser\Node\Stmt\Expression;

use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;

final class HandleFileX509Imports extends AbstractRector
{
  // Collected varnames that refer to phpseclib3\File\X509
  private array $x509Vars = [];
  private array $usedImports = [];
  private bool $isCSR = false;

  private const METHOD_TO_CLASS = [
    'loadX509' => ['phpseclib4\File\X509', 'load'],
    'loadCSR'  => ['phpseclib4\File\CSR', 'loadCSR'],
    'loadCRL'  => ['phpseclib4\File\CRL', 'loadCRL'],
    'loadSPKAC'=> ['phpseclib4\File\CRL', 'loadCRL'],
    'setPrivateKey'=> ['phpseclib4\File\CRL', 'loadCRL'], // Set to CRL per default
    // 'setPrivateKey'=> ['phpseclib4\File\CSR', 'CSR($privKey->getPublicKey())'],
  ];

  public function getNodeTypes(): array
  {
    return [
      Use_::class,
      MethodCall::class,
      Expression::class,
    ];
  }

  public function refactor(Node $node): int|null|Node
  {
    // Remove import for now. We will add the correct one later
    if ($node instanceof Use_) {
      // filter out any UseUse that matches the old class
      $node->uses = array_values(array_filter(
        $node->uses,
        fn($useUse) => ! $this->isName($useUse->name, 'phpseclib3\File\X509')
      ));

      // if no UseUse left, remove the entire Use_ node
      if (count($node->uses) === 0) {
        return NodeTraverser::REMOVE_NODE;
      }
    }

    // Collect varnames that refer to phpseclib3\File\X509
    if ($node instanceof Expression && $node->expr instanceof Assign && $node->expr->expr instanceof New_) {
      if ($this->isNames($node->expr->expr->class, ['X509', 'phpseclib3\File\X509'])) {
        $varName = $this->getName($node->expr->var);
        if ($varName !== null) {
          $this->x509Vars[$varName] = true;
        }
      }
      return null;
    }

    if (!$node instanceof MethodCall) {
      return null;
    }

    if (!$node->var instanceof Variable) {
      return null;
    }

    // Refactor method calls on collected vars
    // varName = x509
    $varName = $this->getName($node->var);
    if ($varName === null || ! isset($this->x509Vars[$varName])) {
      return null;
    }

    $methodName = $this->getName($node->name);

    // check for setPrivateKey
    // setChallenge() or signSPKAC() is a CRL import
    if(in_array($methodName, ['setDnProp', 'signCSR','saveCSR'])) {
      $this->isCSR = true;
      // $this->usedImports[(string) 'phpseclib4\File\CSR'] = true;
    }

    if ($methodName === null || ! isset(self::METHOD_TO_CLASS[$methodName])) {
      return null;
    }

    [$targetClass, $targetMethod] = self::METHOD_TO_CLASS[$methodName];

    $this->usedImports[(string) $targetClass] = true;

    $parts = explode('\\', $targetClass);
    $shortClass = end($parts);

    // add ->getPublicKey() to args for setPrivateKey
    $args = $node->args;
    if ($methodName === 'setPrivateKey' && isset($args[0])) {
      $originalExpr = $args[0]->value;

      $wrappedExpr = new MethodCall(
          $originalExpr,
          new Identifier('getPublicKey')
      );

      $args[0]->value = $wrappedExpr;
    }

    $staticCall = new StaticCall(
      new Name($shortClass),
      $targetMethod,
      $args
    );

    // TODO: afterTraverse
    // if ($methodName === 'setPrivateKey') {
    //   // $csr = new CSR($privKey->getPublicKey());
    //   if($this->isCSR) {
    //     return new Assign(
    //       new Variable('csr'),
    //       new New_(
    //         new Name('CSR'),
    //         $args
    //       )
    //     );
    //   }
    //   // $spkac = CRL::loadCRL(file_get_contents('spkac.txt'));
    //   return new Assign(
    //     new Variable('spkac'),
    //     $staticCall
    //   );
    // }
    return $staticCall;
  }

  private function replaceLoadCRLCalls(Node $node)
  {
    if (
      $node instanceof Expression
      && $node->expr instanceof StaticCall
      && $this->isName($node->expr->name, 'loadCRL')
      && isset($node->expr->args[0])
      && $node->expr->args[0]->value instanceOf MethodCall
      && $this->isName($node->expr->class, 'CRL')
      && $this->isName($node->expr->args[0]->value->var, 'privKey')
      && $this->isName($node->expr->args[0]->value->name, 'getPublicKey')
      ) {
        $args = $node->expr->args;

      dump_node($node);
      if($this->isCSR) {
        $node->expr = new Assign(
          new Variable('csr'),
          new New_(
            new Name('CSR'),
            $args
          )
        );
      } else {
        return new Assign(
          new Variable('spkac'),
          $node->expr
        );
      }

      return $node;
    }

    if (property_exists($node, 'stmts') && is_array($node->stmts)) {
      foreach ($node->stmts as $stmt) {
        $this->replaceLoadCRLCalls($stmt);
      }
    }
    return null;
  }


  public function afterTraverse(array $nodes): ?array
  {
    if(!$this->usedImports || !$this->isCSR) {
      return null;
    }
    $useNodes = [];

    // Add only valid imports
    foreach (array_keys($this->usedImports) as $className) {
      $useNodes[] = new Use_([
        new UseUse(new Name($className))
      ]);
    }
    // No idea why I just can't add this to usedImports
    if($this->isCSR) {
      $useNodes[] = new Use_([
        new UseUse(new Name('phpseclib4\File\CSR'))
      ]);
    }
    $useNodes[] = new Nop();

    // Refactor setPrivateKey
    // Replace all CRL::loadCRL(...) calls
    // TODO: Per class
    foreach ($nodes as $node) {
      $this->replaceLoadCRLCalls($node);
    }

    $this->usedImports = [];
    $this->isCSR = false;

    return array_merge($useNodes, $nodes);
  }
}