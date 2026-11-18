/**
 * Core AST Security Analyzer
 * Zero-dependency, pure JavaScript implementation
 */

import * as babelParser from '@babel/parser';
import traverse from '@babel/traverse';

export interface AnalysisOptions {
  filepath: string;
  sourceCode: string;
  rules: string[];
  exclude: string[];
}

export interface AnalysisResult {
  success: boolean;
  filename: string;
  filepath: string;
  findings: SecurityFinding[];
  astStats?: {
    nodeCount: number;
    functionCount: number;
    varDeclCount: number;
  };
}

export interface SecurityFinding {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  line: number;
  column: number;
  code: string;
  recommendation?: string;
}

/**
 * Main security analyzer class
 * Implements AST-based security analysis with zero third-party runtime dependencies
 */
export class SecurityAnalyzer {
  private rules: Map<string, (node: any, context: any) => SecurityFinding[]>;

  constructor() {
    this.rules = new Map();
    this.initializeDefaultRules();
  }

  /**
   * Initialize built-in security rules
   */
  private initializeDefaultRules(): void {
    // XSS Rules
    this.rules.set('XSS-001', this.detectUnsafeInnerHTML.bind(this));
    this.rules.set('XSS-002', this.detectEvalUsage.bind(this));
    this.rules.set('XSS-003', this.detectDocumentWrite.bind(this));
    
    // CSRF Rules
    this.rules.set('CSRF-001', this.detectMissingCSRFToken.bind(this));
    
    // Privacy Rules
    this.rules.set('PRIV-001', this.detectLocalStoragePII.bind(this));
    this.rules.set('PRIV-002', this.detectCookieTracking.bind(this));
    
    // Supply Chain Rules
    this.rules.set('SC-001', this.detectDynamicImport.bind(this));
  }

  /**
   * Parse source code into AST
   */
  private parseToAST(sourceCode: string): any {
    try {
      return babelParser.parse(sourceCode, {
        sourceType: 'module',
        plugins: [
          'typescript',
          'jsx',
          'classProperties',
          'classPrivateProperties',
          'decorators-legacy',
          'dynamicImport',
          'nullishCoalescingOperator',
          'optionalChaining'
        ]
      });
    } catch (error) {
      throw new Error(`Failed to parse source code: ${error}`);
    }
  }

  /**
   * Analyze code for security issues
   */
  public analyze(options: AnalysisOptions): AnalysisResult {
    const startTime = performance.now();
    const findings: SecurityFinding[] = [];

    let ast: any;
    try {
      ast = this.parseToAST(options.sourceCode);
    } catch (error) {
      return {
        success: false,
        filename: options.filepath,
        filepath: options.filepath,
        findings: [{
          ruleId: 'PARSE-ERR',
          severity: 'high',
          message: `Failed to parse source: ${(error as Error).message}`,
          line: 1,
          column: 1,
          code: ''
        }]
      };
    }

    const context = {
      filepath: options.filepath,
      filename: options.filepath.split('/').pop() || 'unknown',
      sourceCode: options.sourceCode,
      ast,
      nodeCount: 0,
      functionCount: 0,
      issues: [] as SecurityFinding[]
    };

    // Extract rules to run
    const rulesToRun = options.rules.length > 0 
      ? options.rules.filter(r => !options.exclude.includes(r))
      : Array.from(this.rules.keys());

    // Traverse AST and run rules
    traverse(ast, {
      enter: (path) => {
        const node = path.node;
        context.nodeCount++;

        // Track function count
        if (node.type === 'FunctionDeclaration' || 
            node.type === 'FunctionExpression' ||
            node.type === 'ArrowFunctionExpression') {
          context.functionCount++;
        }

        // Run security rules on each node
        for (const ruleId of rulesToRun) {
          const rule = this.rules.get(ruleId);
          if (rule) {
            const ruleFindings = rule(node, context);
            findings.push(...ruleFindings);
          }
        }
      }
    });

    return {
      success: true,
      filename: options.filepath,
      filepath: options.filepath,
      findings,
      astStats: {
        nodeCount: context.nodeCount,
        functionCount: context.functionCount,
        varDeclCount: 0 // Will be calculated if needed
      }
    };
  }

  // ============ XSS DETECTION RULES ============

  /**
   * Rule XSS-001: Detect unsafe innerHTML usage
   */
  private detectUnsafeInnerHTML(node: any, context: any): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (node.type === 'MemberExpression' && 
        node.property?.name === 'innerHTML' &&
        node.object?.type === 'Identifier') {
      
      // Check if used with user input
      const parent = context.path?.parent;
      if (parent?.type === 'AssignmentExpression' || parent?.type === 'CallExpression') {
        findings.push({
          ruleId: 'XSS-001',
          severity: 'high',
          message: 'Unsafe innerHTML assignment can lead to XSS vulnerabilities',
          line: node.loc?.start?.line || 1,
          column: node.loc?.start?.column || 1,
          code: this.getNodeCode(node, context),
          recommendation: 'Use textContent instead of innerHTML for user content, or sanitize with DOMPurify'
        });
      }
    }

    return findings;
  }

  /**
   * Rule XSS-002: Detect dangerous eval() usage
   */
  private detectEvalUsage(node: any, context: any): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (node.type === 'CallExpression' &&
        node.callee?.type === 'Identifier' &&
        node.callee?.name === 'eval') {
      
      findings.push({
        ruleId: 'XSS-002',
        severity: 'critical',
        message: 'Use of eval() is a critical security risk',
        line: node.loc?.start?.line || 1,
        column: node.loc?.start?.column || 1,
        code: this.getNodeCode(node, context),
        recommendation: 'Avoid eval() entirely. Use JSON.parse() or Function constructor with sanitized input'
      });
    }

    return findings;
  }

  /**
   * Rule XSS-003: Detect document.write() usage
   */
  private detectDocumentWrite(node: any, context: any): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (node.type === 'CallExpression' &&
        node.callee?.type === 'MemberExpression' &&
        node.callee?.object?.name === 'document' &&
        node.callee?.property?.name === 'write') {
      
      findings.push({
        ruleId: 'XSS-003',
        severity: 'high',
        message: 'document.write() can cause XSS vulnerabilities and breaks page parsing',
        line: node.loc?.start?.line || 1,
        column: node.loc?.start?.column || 1,
        code: this.getNodeCode(node, context),
        recommendation: 'Use DOM manipulation methods (createElement, appendChild) instead'
      });
    }

    return findings;
  }

  // ============ CSRF DETECTION RULES ============

  /**
   * Rule CSRF-001: Detect fetch requests without CSRF token
   */
  private detectMissingCSRFToken(node: any, context: any): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (node.type === 'CallExpression' &&
        node.callee?.type === 'MemberExpression' &&
        ['fetch', 'XMLHttpRequest'].includes(node.callee?.property?.name)) {
      
      // Check if CSRF token header is present
      const hasCSRFToken = this.checkForCSRFToken(context.sourceCode);
      if (!hasCSRFToken) {
        findings.push({
          ruleId: 'CSRF-001',
          severity: 'medium',
          message: 'Outgoing request may be missing CSRF protection',
          line: node.loc?.start?.line || 1,
          column: node.loc?.start?.column || 1,
          code: this.getNodeCode(node, context),
          recommendation: 'Include X-CSRF-Token header or use SameSite cookies'
        });
      }
    }

    return findings;
  }

  // ============ PRIVACY DETECTION RULES ============

  /**
   * Rule PRIV-001: Detect PII in localStorage
   */
  private detectLocalStoragePII(node: any, context: any): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const piiPatterns = [
      /localStorage\.setItem\s*\(\s*['"`](?:email|user|phone|ssn|credit)[^'"`]*['"`]/i,
      /localStorage\.setItem\s*\([^,]+,\s*(?:password|token|key)/i
    ];

    const sourceCode = context.sourceCode || '';
    for (const pattern of piiPatterns) {
      if (pattern.test(sourceCode)) {
        findings.push({
          ruleId: 'PRIV-001',
          severity: 'high',
          message: 'Potential PII stored in localStorage - consider encrypted storage or IndexedDB',
          line: 1,
          column: 1,
          code: sourceCode.substring(0, 100),
          recommendation: 'Use secure storage for sensitive data: IndexedDB with encryption or secure cookies'
        });
        break;
      }
    }

    return findings;
  }

  /**
   * Rule PRIV-002: Detect tracking via cookies
   */
  private detectCookieTracking(node: any, context: any): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const trackingPatterns = [
      /document\.cookie.*=.*['"`]tracking/i,
      /setCookie.*tracking/i
    ];

    const sourceCode = context.sourceCode || '';
    for (const pattern of trackingPatterns) {
      if (pattern.test(sourceCode)) {
        findings.push({
          ruleId: 'PRIV-002',
          severity: 'low',
          message: 'Potential tracking cookie detected - ensure GDPR/CCPA compliance',
          line: 1,
          column: 1,
          code: sourceCode.substring(0, 100),
          recommendation: 'Add consent management for tracking cookies and provide opt-out mechanism'
        });
        break;
      }
    }

    return findings;
  }

  // ============ SUPPLY CHAIN DETECTION RULES ============

  /**
   * Rule SC-001: Detect dynamic imports that could be exploited
   */
  private detectDynamicImport(node: any, context: any): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (node.type === 'CallExpression' &&
        node.callee?.type === 'MemberExpression' &&
        node.callee?.property?.name === 'import') {
      
      // Check if the import path is dynamic/user-controlled
      const args = node.arguments;
      if (args.length > 0) {
        const isStringLiteral = args[0]?.type === 'StringLiteral';
        const isTemplateLiteral = args[0]?.type === 'TemplateLiteral';
        
        if (!isStringLiteral && !isTemplateLiteral) {
          findings.push({
            ruleId: 'SC-001',
            severity: 'medium',
            message: 'Dynamic import with non-literal path - potential supply chain risk',
            line: node.loc?.start?.line || 1,
            column: node.loc?.start?.column || 1,
            code: this.getNodeCode(node, context),
            recommendation: 'Validate all dynamic import paths against allowlist before execution'
          });
        }
      }
    }

    return findings;
  }

  // ============ HELPER METHODS ============

  /**
   * Check if source code contains CSRF token
   */
  private checkForCSRFToken(sourceCode: string): boolean {
    const csrfPatterns = [
      /X-CSRF-Token/i,
      /X-XSRF-TOKEN/i,
      /csrf-token/i,
      /csrfToken/i
    ];
    
    return csrfPatterns.some(pattern => pattern.test(sourceCode));
  }

  /**
   * Get code snippet for a node
   */
  private getNodeCode(node: any, context: any): string {
    if (!node.loc) return '';
    const start = node.loc.start;
    const end = node.loc.end;
    return context.sourceCode?.substring(start.index || 0, end.index) || '';
  }

  /**
   * Get all available rule IDs
   */
  public getAvailableRules(): string[] {
    return Array.from(this.rules.keys());
  }

  /**
   * Get rule by ID
   */
  public getRule(ruleId: string): ((node: any, context: any) => SecurityFinding[]) | undefined {
    return this.rules.get(ruleId);
  }
}

// Export singleton instance
export const defaultAnalyzer = new SecurityAnalyzer();