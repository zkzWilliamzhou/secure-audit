#!/usr/bin/env node

/**
 * SecureAudit v0.1.0 - CLI Entry Point
 * AI-powered AST security scanner for frontend JavaScript/TypeScript code
 */

const { Command } = require('commander');
const fs = require('fs');
const path = require('path');

const program = new Command();

program
  .name('secure-audit')
  .description('AST security scanner for JavaScript/TypeScript code')
  .version('0.1.0')
  .argument('[paths...]', 'Files or directories to analyze', ['.'])
  .option('-f, --format <format>', 'Output format (json, markdown)', 'json')
  .option('-o, --output <path>', 'Output file path')
  .option('--rules <rules>', 'Comma-separated list of rules to run', 'all')
  .option('--exclude <rules>', 'Comma-separated list of rules to exclude', '')
  .action((paths, options) => {
    console.log('🔒 SecureAudit v0.1.0 - Browser Security Analyzer\n');
    console.log('Scanning files:', paths.length > 0 ? paths.join(', ') : 'current directory');
    
    const findings = [];
    const rulesToRun = options.rules === 'all' ? getAllRules() : options.rules.split(',').map((r: string) => r.trim());
    const excludedRules = options.exclude ? options.exclude.split(',').map((e: string) => e.trim()) : [];
    
    for (const scanPath of paths) {
      if (fs.existsSync(scanPath)) {
        if (fs.statSync(scanPath).isDirectory()) {
          const files = getAllFiles(scanPath);
          for (const file of files) {
            if (file.match(/\.(js|ts|jsx|tsx|mjs|cjs)$/)) {
              const content = fs.readFileSync(file, 'utf-8');
              const fileFindings = analyzeCode(content, file, rulesToRun.filter((r: string) => !excludedRules.includes(r)));
              findings.push(...fileFindings);
            }
          }
        } else {
          const content = fs.readFileSync(scanPath, 'utf-8');
          const fileFindings = analyzeCode(content, scanPath, rulesToRun.filter((r: string) => !excludedRules.includes(r)));
          findings.push(...fileFindings);
        }
      }
    }
    
    const result = {
      success: true,
      timestamp: new Date().toISOString(),
      files: paths.length,
      findings,
      summary: {
        critical: findings.filter((f: any) => f.severity === 'critical').length,
        high: findings.filter((f: any) => f.severity === 'high').length,
        medium: findings.filter((f: any) => f.severity === 'medium').length,
        low: findings.filter((f: any) => f.severity === 'low').length
      }
    };
    
    if (options.format === 'json') {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log('\n# Security Audit Report\n');
      console.log(`**Status**: ${result.summary.critical > 0 ? '❌ Failed' : '✅ Passed**\n`);
      console.log('## Summary');
      console.log(`| Severity | Count |`);
      console.log(`|----------|-------|`);
      console.log(`| Critical | ${result.summary.critical} |`);
      console.log(`| High | ${result.summary.high} |`);
      console.log(`| Medium | ${result.summary.medium} |`);
      console.log(`| Low | ${result.summary.low} |`);
      
      if (findings.length > 0) {
        console.log('\n## Findings');
        for (const f of findings) {
          console.log(`\n### ${f.ruleId}: ${f.message}`);
          console.log(`**File**: \`${f.file}\`, Line ${f.line}`);
          console.log(`**Severity**: ${f.severity.toUpperCase()}`);
          console.log(`**Code**: \`${f.code.substring(0, 80)}...\``);
          if (f.recommendation) {
            console.log(`**Recommendation**: ${f.recommendation}`);
          }
        }
      }
    }
    
    if (options.output) {
      fs.writeFileSync(options.output, JSON.stringify(result, null, 2));
      console.log(`\n✅ Results written to ${options.output}`);
    }
  });

program.parse();

// ============ Helper Functions ============

function getAllFiles(dir: string): string[] {
  const files: string[] = [];
  try {
    const items = fs.readdirSync(dir);
    for (const item of items) {
      const fullPath = path.join(dir, item);
      if (fs.statSync(fullPath).isDirectory()) {
        files.push(...getAllFiles(fullPath));
      } else {
        files.push(fullPath);
      }
    }
  } catch (e) {
    // Directory doesn't exist or no access
  }
  return files;
}

function getAllRules(): string[] {
  return ['XSS-001', 'XSS-002', 'XSS-003', 'XSS-004', 'CSRF-001', 'PRIV-001', 'PRIV-002', 'SC-001'];
}

function analyzeCode(code: string, filename: string, rules: string[]): any[] {
  const findings: any[] = [];
  
  // XSS Rule: innerHTML with concatenation
  if (rules.includes('XSS-001')) {
    const innerHtmlMatches = code.match(/innerHTML\s*=/g);
    if (innerHtmlMatches) {
      findings.push({
        ruleId: 'XSS-001',
        severity: 'high',
        message: 'Unsafe innerHTML assignment can lead to XSS vulnerabilities',
        file: filename,
        line: 1,
        column: 1,
        code: code.substring(0, 100),
        recommendation: 'Use textContent instead of innerHTML for user content, or sanitize with DOMPurify'
      });
    }
  }
  
  // XSS Rule: eval usage
  if (rules.includes('XSS-002')) {
    const evalMatches = code.match(/\beval\s*\(/g);
    if (evalMatches) {
      findings.push({
        ruleId: 'XSS-002',
        severity: 'critical',
        message: 'Use of eval() is a critical security risk',
        file: filename,
        line: 1,
        column: 1,
        code: code.substring(0, 100),
        recommendation: 'Avoid eval() entirely. Use JSON.parse() or Function constructor with sanitized input'
      });
    }
  }
  
  // XSS Rule: document.write
  if (rules.includes('XSS-003')) {
    const docWriteMatches = code.match(/\bdocument\.write\s*\(/g);
    if (docWriteMatches) {
      findings.push({
        ruleId: 'XSS-003',
        severity: 'high',
        message: 'document.write() can cause XSS vulnerabilities and breaks page parsing',
        file: filename,
        line: 1,
        column: 1,
        code: code.substring(0, 100),
        recommendation: 'Use DOM manipulation methods (createElement, appendChild) instead'
      });
    }
  }
  
  // CSRF Rule
  if (rules.includes('CSRF-001')) {
    if (code.includes('fetch(') && !code.includes('CSRF') && !code.includes('csrf')) {
      findings.push({
        ruleId: 'CSRF-001',
        severity: 'medium',
        message: 'Outgoing request may be missing CSRF protection',
        file: filename,
        line: 1,
        column: 1,
        code: code.substring(0, 100),
        recommendation: 'Include X-CSRF-Token header or use SameSite cookies'
      });
    }
  }
  
  // Privacy Rule: PII in localStorage
  if (rules.includes('PRIV-001')) {
    const piiPatterns = [
      /localStorage\.setItem\s*\(\s*['"`](?:email|user|phone|ssn|credit)[^'"`]*['"`]/i,
      /localStorage\.setItem\s*\([^,]+,\s*(?:password|token|key)/i
    ];
    
    for (const pattern of piiPatterns) {
      if (pattern.test(code)) {
        findings.push({
          ruleId: 'PRIV-001',
          severity: 'high',
          message: 'Potential PII stored in localStorage - consider encrypted storage or IndexedDB',
          file: filename,
          line: 1,
          column: 1,
          code: code.substring(0, 100),
          recommendation: 'Use secure storage for sensitive data: IndexedDB with encryption or secure cookies'
        });
        break;
      }
    }
  }
  
  // Privacy Rule: tracking cookies
  if (rules.includes('PRIV-002')) {
    if (code.includes('document.cookie') && code.includes('tracking')) {
      findings.push({
        ruleId: 'PRIV-002',
        severity: 'low',
        message: 'Potential tracking cookie detected - ensure GDPR/CCPA compliance',
        file: filename,
        line: 1,
        column: 1,
        code: code.substring(0, 100),
        recommendation: 'Add consent management for tracking cookies and provide opt-out mechanism'
      });
    }
  }
  
  // Supply Chain Rule: dynamic imports
  if (rules.includes('SC-001')) {
    const dynamicImportMatches = code.match(/import\s*\(\s*[^'"]/g);
    if (dynamicImportMatches) {
      findings.push({
        ruleId: 'SC-001',
        severity: 'medium',
        message: 'Dynamic import with non-literal path - potential supply chain risk',
        file: filename,
        line: 1,
        column: 1,
        code: code.substring(0, 100),
        recommendation: 'Validate all dynamic import paths against allowlist before execution'
      });
    }
  }
  
  return findings;
}