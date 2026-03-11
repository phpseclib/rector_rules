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

use Rector\Rector\AbstractRector;

final class X509 extends AbstractRector
{
  // Collected varnames that refer to phpseclib3\File\X509
  private array $x509Vars = [];
  private array $usedImports = [];
  private bool $isCSR = false;
  private bool $isX509 = false;
  private string $privKeyObj = '';
  private string $pubKeyObj = '';
  private ?string $subjectVar = null;
  private ?string $issuerVar = null;

  // targetClass, targetMethod
  private const METHOD_TO_CLASS = [
    'loadX509' => ['phpseclib4\File\X509', 'load'],
    'loadCSR'  => ['phpseclib4\File\CSR', 'loadCSR'],
    'loadCRL'  => ['phpseclib4\File\CRL', 'loadCRL'],
    'loadSPKAC'=> ['phpseclib4\File\CRL', 'loadCRL'],
    'setPrivateKey'=> ['phpseclib4\File\CRL', 'loadCRL'], // Set to CRL per default
    // 'setPrivateKey'=> ['phpseclib4\File\CSR', 'new CSR($privKey->getPublicKey())'],
  ];

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

  public function reset() {
    $this->isCSR = false;
    $this->isX509 = false;
    $this->subjectVar = null;
    $this->issuerVar = null;
    $this->privKeyObj = '';
    $this->pubKeyObj = '';
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
      $this->reset();

      if ($node->getAttribute(X509NodeVisitor::IS_X509, false)) {
        $this->isX509 = true;
        $this->pubKeyObj = $node->getAttribute(X509NodeVisitor::PUB_KEY_OBJ, '');

        $this->issuerVar = $node->getAttribute(X509NodeVisitor::ISSUER_VAR);
        $this->subjectVar = $node->getAttribute(X509NodeVisitor::SUBJECT_VAR);
      }

      if ($node->getAttribute(X509NodeVisitor::IS_CSR, false)) {
        $this->isCSR = true;
        $this->x509Vars['csr'] = true;
      }

      $this->privKeyObj = $node->getAttribute(X509NodeVisitor::PRIV_KEY_OBJ, '');
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
        if ($varName !== null) {
          $this->x509Vars[$varName] = true;
        }

        if ($this->isX509 && $node->expr->getAttribute(X509NodeVisitor::IS_FIRST_X509_ASSIGNMENT, false)) {
          return new Expression(
            new Assign(
              new Variable('x509'),
              new New_(
                new Name('X509'),
                [new Arg(new Variable($this->pubKeyObj))]
              )
            )
          );
        }

        return NodeTraverser::REMOVE_NODE;
      }
      return null;
    }

    // Delete validateDate()
    // This is handled by validateSignature() now
    if ($node instanceof Expression) {
      $expr = $node->expr;
      if ($expr instanceof MethodCall) {
        $call = $expr;
      } elseif ($expr instanceof Assign && $expr->expr instanceof MethodCall) {
        $call = $expr->expr;
      } else {
        return null;
      }

      if (
        $call->var instanceof Variable &&
        isset($this->x509Vars[$this->getName($call->var)]) &&
        $this->isName($call->name, 'validateDate')
      ) {
        return NodeTraverser::REMOVE_NODE;
      }
    }

    if (
      $node instanceof Expression &&
      $node->expr instanceof Assign &&
      $node->expr->expr instanceof MethodCall &&
      isset($this->x509Vars[$node->expr->expr->var->name]) &&
      $this->isNames($node->expr->expr->name, ['signCSR', 'signSPKAC'])
    ) {
      return new Expression(new Methodcall(
        new Variable($this->privKeyObj),
        'sign',
        [new Arg($node->expr->var)]
      ));
    }

    // Handle X509
    if($this->isX509) {
      // $result = $x509->sign($issuer, $subject) to $privKey->sign($x509)
      if (
        $node instanceof Expression &&
        $node->expr instanceof Assign &&
        $node->expr->expr instanceof MethodCall &&
        isset($this->x509Vars[$node->expr->expr->var->name]) &&
        $this->isName($node->expr->expr->name, 'sign')
      ) {
        return new Expression(new Methodcall(
          new Variable($this->privKeyObj),
          'sign',
          [new Arg($node->expr->expr->var)]
        ));
      }

      // Remove setPublicKey() and setPrivateKey() for X509
      if (
        $node instanceof Expression &&
        $node->expr instanceof MethodCall
      ) {
        $methodCall = $node->expr;
        if (!$methodCall->var instanceof Variable) {
          return null;
        }
        if($this->isNames($methodCall->name, ['setPublicKey', 'setPrivateKey'])) {
          return NodeTraverser::REMOVE_NODE;
        }
      }
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
          return new Assign(
            new Variable('csr'),
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
      case 'setDN':
        if (!$this->isX509) {
          return null;
        }
        if ($varName === $this->subjectVar) {
          $node->var = new Variable('x509');
          $node->name = new Identifier('setSubjectDN');
        }
        if ($varName === $this->issuerVar) {
          $node->var = new Variable('x509');
          $node->name = new Identifier('setIssuerDN');
        }
        return $node;

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
        if($this->isCSR) {
          $node->var = new Variable('csr');
        }
        return $node;

      case 'saveCSR':
        return new Methodcall(
          $node->args[0]->value,
          new Identifier('toString')
        );

      case 'saveX509':
        return new Methodcall(
          $node->var,
          new Identifier('toString')
      );

      case 'setChallenge':
        $node->var = new Variable('spkac');
        return $node;

      default:
        return null;
    }
  }
}
