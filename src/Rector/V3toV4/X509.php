<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use PhpParser\NodeTraverser;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Name;
use PhpParser\Node\Identifier;
use PhpParser\Node\UseItem;
use PhpParser\Node\Stmt\Use_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use Rector\PhpParser\Node\FileNode;

use Rector\PhpParser\Node\BetterNodeFinder;
use Rector\Rector\AbstractRector;

final class X509 extends AbstractRector
{
  // Collected varnames that refer to phpseclib3\File\X509
  private array $x509Vars = [];
  private string $varName = '';
  private array $usedImports = [];
  private bool $isCSR = false;

  private const METHOD_TO_CLASS = [
    'loadX509' => ['phpseclib4\File\X509', 'load'],
    'loadCSR'  => ['phpseclib4\File\CSR', 'loadCSR'],
    'loadCRL'  => ['phpseclib4\File\CRL', 'loadCRL'],
    'loadSPKAC'=> ['phpseclib4\File\CRL', 'loadCRL'],
    'setPrivateKey'=> ['phpseclib4\File\CRL', 'loadCRL'], // Set to CRL per default
    // 'setPrivateKey'=> ['phpseclib4\File\CSR', 'new CSR($privKey->getPublicKey())'],
  ];

  public function __construct(
    private BetterNodeFinder $betterNodeFinder
  ) {}

  public function getNodeTypes(): array
  {
    return [
      FileNode::class,
      Class_::class,
      MethodCall::class,
      Expression::class,
    ];
  }

  public function stmtsWithoutLegacyImport($stmts) {
    return array_values(array_filter($stmts, function ($stmt) {
      if (!$stmt instanceof Use_) {
        return true;
      }

      $stmt->uses = array_values(array_filter($stmt->uses, fn(UseItem $useItem) =>
        !$this->isName($useItem->name, 'phpseclib3\File\X509')
      ));

      // Keep Use_ only if it has at least one UseItem left
      return count($stmt->uses) > 0;
    }));
  }

  public function refactor(Node $node): int|null|Node
  {
    if($node instanceof FileNode) {
      $this->usedImports = $node->getAttribute('usedImports', []);
      // Remove old import
      $node->stmts = $this->stmtsWithoutLegacyImport($node->stmts);

      $newImportNodes = [];
      foreach(array_keys($this->usedImports) as $className) {
        $newImportNodes[] = new Use_([new UseItem(new Name($className))]);
      }
      $node->stmts = array_merge($newImportNodes, $node->stmts);
      return $node;
    }

    if($node instanceof Class_) {
      // A file can have several classes, so reset for the new class
      $this->isCSR = false;
      if ($node->getAttribute(X509NodeVisitor::IS_CSR, false)) {
        $this->isCSR = true;
      }
      return null;
    }

    // Collect varnames that refer to phpseclib3\File\X509
    // And delete instance
    if ($node instanceof Expression
      && $node->expr instanceof Assign
      && $node->expr->expr instanceof New_
    ) {
      if ($this->isNames($node->expr->expr->class, ['X509', 'phpseclib3\File\X509'])) {
        $varName = $this->getName($node->expr->var);
        $this->varName = $node->expr->var->name;
        if ($varName !== null) {
          $this->x509Vars[$varName] = true;
        }
        return NodeTraverser::REMOVE_NODE;
      }
      return null;
    }

    // Delete validateDate()
    // This is handled by validateSignature() now
    $validateDateCalls = $this->betterNodeFinder->find($node, function(Node $n) {
      return $n instanceof MethodCall
        && $n->var instanceof Variable
        && isset($this->x509Vars[$n->var->name])
        && $this->isName($n->name, 'validateDate');
    });
    foreach ($validateDateCalls as $call) {
      return NodeTraverser::REMOVE_NODE;
    }

    if (
      $node instanceof Expression &&
      $node->expr instanceof Assign &&
      $node->expr->expr instanceof MethodCall &&
      isset($this->x509Vars[$node->expr->expr->var->name]) &&
      $this->isName($node->expr->expr->name, 'signCSR')
    ) {
      return new Expression(new Methodcall(
        // TODO: currently privKey is hardcoded. change it so that this comes from setPrivateKey
        new Variable('privKey'),
        'sign',
        [new Arg($node->expr->var)]
      ));
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
    if ($methodName === null) {
      return null;
    }

    if(isset(self::METHOD_TO_CLASS[$methodName])) {
      [$targetClass, $targetMethod] = self::METHOD_TO_CLASS[$methodName];
      $parts = explode('\\', $targetClass);
      $shortClass = end($parts);

      // add ->getPublicKey() to args for setPrivateKey
      $args = $node->args;
      if ($methodName === 'setPrivateKey' && isset($args[0])) {
        $wrappedExpr = new MethodCall(
            $args[0]->value,
            new Identifier('getPublicKey')
        );
        $args[0]->value = $wrappedExpr;
      }

      $staticCall = new StaticCall(
        new Name($shortClass),
        $targetMethod,
        $args
      );

      if ($methodName === 'setPrivateKey') {
        // $csr = new CSR($privKey->getPublicKey());
        if($this->isCSR) {
          $this->x509Vars['csr'] = true;
          $this->varName = 'csr';
          return new Assign(
            new Variable($this->varName),
            new New_(
              new Name('CSR'),
              $args
            )
          );
        }
        // $spkac = CRL::loadCRL(file_get_contents('spkac.txt'));
        return new Assign(
          new Variable('spkac'),
          $staticCall
        );
      }
      return $staticCall;
    }

    switch ($methodName) {
      case 'getDN':
        $node->name = new Identifier('getSubjectDN');
        // Add X509::DN_ARRAY only if no argument present
        if (count($node->args) === 0) {
          $node->args[0] = new Arg(
            new ClassConstFetch(
              new Name('X509'),
              'DN_ARRAY'
            )
          );
        }
        return $node;

      case 'setDNProp':
        $node->name = new Identifier('addDNProp');
        $node->var = new Variable($this->varName);
        return $node;

      case 'saveCSR':
        return new Methodcall(
          $node->args[0]->value,
          new Identifier('toString')
        );

      default:
        return null;
    }
  }
}
