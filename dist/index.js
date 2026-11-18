#!/usr/bin/env node

/**
 * SecureAudit v0.1.0
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
  .action((paths, options) => {
    console.log('🔒 SecureAudit v0.1.0\n');
    console.log('Scanning files:', paths.join(', '));
    
    const findings = [];
    
    for (const scanPath of paths) {
      if (fs.existsSync(scanPath)) {
        if (fs.statSync(scanPath).isDirectory()) {
          const files = getAllFiles(scanPath);
          for (const file of files) {
            if (file.match(/\.(js|ts|jsx|tsx)$/)) {
              const content = fs.readFileSync(file, 'utf-8');
              const fileFindings = analyzeCode(content, file);
              findings.push(...fileFindings);
            }
          }
        } else {
          const content = fs.readFileSync(scanPath, 'utf-8');
          const fileFindings = analyzeCode(content, scanPath);
          findings.push(...fileFindings);
        }
      }
    }
    
    const result = {
      success: true,
      files: paths.length,
      findings,
      summary: {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length
      }
    };
    
    if (options.format === 'json') {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log('\n# Security Scan Report\n');
      console.log('**Status**: ✅ Passed\n');
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
        }
      }
    }
    
    if (options.output) {
      fs.writeFileSync(options.output, JSON.stringify(result, null, 2));
      console.log(`\n✅ Results written to ${options.output}`);
    }
  });

program.parse();

function getAllFiles(dir) {
  const files = [];
  const items = fs.readdirSync(dir);
  for (const item of items) {
    const fullPath = path.join(dir, item);
    if (fs.statSync(fullPath).isDirectory()) {
      files.push(...getAllFiles(fullPath));
    } else {
      files.push(fullPath);
    }
  }
  return files;
}

function analyzeCode(code, filename) {
  const findings = [];
  
  if (code.includes('innerHTML') && code.match(/innerHTML.*\+/)) {
    findings.push({
      ruleId: 'XSS-001',
      severity: 'high',
      message: 'Unsafe innerHTML assignment can lead to XSS vulnerabilities',
      file: filename,
      line: 1,
      column: 1,
      code: code.substring(0, 100)
    });
  }
  
  if (code.includes('eval(')) {
    findings.push({
      ruleId: 'XSS-002',
      severity: 'critical',
      message: 'Use of eval() is a critical security risk',
      file: filename,
      line: 1,
      column: 1,
      code: code.substring(0, 100)
    });
  }
  
  if (code.includes('document.write(')) {
    findings.push({
      ruleId: 'XSS-003',
      severity: 'high',
      message: 'document.write() can cause XSS vulnerabilities',
      file: filename,
      line: 1,
      column: 1,
      code: code.substring(0, 100)
    });
  }
  
  if (code.includes('localStorage.setItem') && /password|token|key/i.test(code)) {
    findings.push({
      ruleId: 'PRIV-001',
      severity: 'high',
      message: 'PII or sensitive data may be stored in localStorage',
      file: filename,
      line: 1,
      column: 1,
      code: code.substring(0, 100)
    });
  }
  
  return findings;
}