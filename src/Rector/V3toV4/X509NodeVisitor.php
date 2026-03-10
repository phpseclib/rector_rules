<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use PhpParser\Node;
use PhpParser\Node\Identifier;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Name\FullyQualified;
use Rector\PhpParser\Node\FileNode;
use Rector\PhpParser\Node\BetterNodeFinder;

use PhpParser\NodeVisitorAbstract;
use Rector\Contract\PhpParser\DecoratingNodeVisitorInterface;

use phpseclib\rectorRules\Rector\V3toV4\HandleFileX509Imports;

final class X509NodeVisitor extends NodeVisitorAbstract implements DecoratingNodeVisitorInterface
{
  public const IS_CSR = 'is_csr';
  public const IS_X509 = 'is_x509';
  public const IS_FIRST_X509_ASSIGNMENT = 'is_fist_x509_assignment';
  public const PRIV_KEY_OBJ = '';
  public const PUB_KEY_OBJ = '';
  public const SUBJECT_VAR = 'subject_var';
  public const ISSUER_VAR = 'issuer_var';

  private const METHOD_TO_CLASS = [
    'loadX509' => 'phpseclib4\File\X509',
    'getDN' => 'phpseclib4\File\X509',
    'loadCSR'  => 'phpseclib4\File\CSR',
    'loadCRL'  => 'phpseclib4\File\CRL',
    'loadSPKAC'=> 'phpseclib4\File\CRL',
  ];

  public function __construct(
    private BetterNodeFinder $betterNodeFinder
  ) {}

  public function getNodeTypes(): array
  {
    return [FileNode::class];
  }

  public function enterNode(Node $node): ?Node
  {
    if (!$node instanceof FileNode) {
      return null;
    }
    $usedImports = [];

    $classes = $this->betterNodeFinder->findInstanceOf($node->stmts, Class_::class);
    foreach ($classes as $class) {
      $hasCsrMethodCall = false;
      $hasX509MethodCall = false;

      $hasSetPrivateKey = false;
      $hasSetPublicKey = false;

      $privKeyObj = null;
      $pubKeyObj = null;

      $issuerVar = null;
      $subjectVar = null;

      $methodCalls = $this->betterNodeFinder->findInstanceOf($class, MethodCall::class);
      foreach ($methodCalls as $methodCall) {
        if (!$methodCall->name instanceof Identifier) {
          continue;
        }
        $methodName = $methodCall->name->toString();

        $varName = is_string($methodCall->var->name) ? $methodCall->var->name : null;

        if ($methodName === 'setPrivateKey') {
          $hasSetPrivateKey = true;
          // Store the privateKey object to use it later for signing
          $arg = $methodCall->args[0]->value;
          if ($arg instanceof Variable && is_string($arg->name)) {
            $privKeyObj = $arg->name;
          }
          $issuerVar = $varName;
        }

        if ($methodName === 'setPublicKey') {
          $hasSetPublicKey = true;
          // Store the publicKey object to use it later for X509 instantiation
          $arg = $methodCall->args[0]->value;
          if ($arg instanceof Variable && is_string($arg->name)) {
            $pubKeyObj = $arg->name;
          }
          $subjectVar = $varName;
        }

        if (in_array($methodName, ['loadCSR','signCSR','saveCSR'], true)) {
          $hasCsrMethodCall = true;
        }
        if (in_array($methodName, ['setPublicKey', 'saveX509', 'setDN'], true)) {
          $hasX509MethodCall = true;
        }

        if (isset(self::METHOD_TO_CLASS[$methodName])) {
          $usedImports[self::METHOD_TO_CLASS[$methodName]] = true;
        }
      }
      // Set isCSR attribute on Class_
      if ($hasCsrMethodCall) {
        $class->setAttribute(self::IS_CSR, true);
      }
      // It is a x509 class
      if ($hasX509MethodCall) {
        $class->setAttribute(self::IS_X509, true);

        // Get the first of 3 assignments
        $x509Assignments = $this->betterNodeFinder->find($class, function(Node $assign) {
          return $assign instanceof Assign
            && $assign->expr instanceof New_
            && in_array($assign->expr->class->toString(), ['X509', 'phpseclib3\File\X509'], true);
        });

        // If we have see exactly 3 assignments, they are for sure subject, issuer and x509
        if (count($x509Assignments) === 3) {
          // Set attribute on Assignment
          $x509Assignments[0]->setAttribute(self::IS_FIRST_X509_ASSIGNMENT, true);
        }
      }
      if ($hasSetPublicKey) {
        $class->setAttribute(self::PUB_KEY_OBJ, $pubKeyObj);
      }
      if ($subjectVar !== null) {
        $class->setAttribute(self::SUBJECT_VAR, $subjectVar);
      }
      if ($issuerVar !== null) {
        $class->setAttribute(self::ISSUER_VAR, $issuerVar);
      }

      // setPrivateKey can be used by CSR and CRL
      if ($hasSetPrivateKey) {
        $class->setAttribute(self::PRIV_KEY_OBJ, $privKeyObj);

        if ($class->getAttribute(self::IS_CSR, false)) {
          $usedImports['phpseclib4\File\CSR'] = true;
        } elseif ($class->getAttribute(self::IS_X509, false)) {
          $usedImports['phpseclib4\File\X509'] = true;
        } else {
          $usedImports['phpseclib4\File\CRL'] = true;
        }
      }
    }
    // set usedImports on the FileNode
    $node->setAttribute('usedImports', $usedImports);
    return null;
  }
}
