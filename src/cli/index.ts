#!/usr/bin/env node

/**
 * SecureAudit CLI Entry Point
 * Zero-dependency, pure JavaScript implementation
 */

import { Command } from 'commander';
import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { SecurityAnalyzer } from '../analyzer/index.js';
import { formatOutput } from '../output/formatter.js';
import chalk from 'chalk';

const program = new Command();

program
  .name('secure-audit')
  .description('AI-powered AST security scanner for frontend JavaScript/TypeScript code')
  .version('0.1.0')
  .option('-c, --config <path>', 'Path to configuration file')
  .option('-r, --rules <rules>', 'Comma-separated list of rules to run', 'all')
  .option('-e, --exclude <exclude>', 'Comma-separated list of rules to exclude', '')
  .option('-f, --format <format>', 'Output format (json, markdown, sarif, html)', 'json')
  .option('-o, --output <path>', 'Output file path')
  .option('--fix', 'Automatically fix fixable issues')
  .option('--ai', 'Enable AI-enhanced analysis (experimental)')
  .option('-v, --verbose', 'Enable verbose output')
  .argument('[paths...]', 'Files or directories to analyze', ['.'])
  .action(async (paths, options) => {
    const startTime = performance.now();

    // Parse rules
    const rules = options.rules === 'all' ? 'all' : options.rules.split(',').map((r: string) => r.trim());
    const exclude = options.exclude ? options.exclude.split(',').map((e: string) => e.trim()) : [];
    
    const analyzer = new SecurityAnalyzer();
    const results = [];
    const findings = [];
    let filesProcessed = 0;

    // Process each path
    for (const path of paths) {
      const pathResults = await processPath(path, analyzer, rules, exclude);
      results.push(...pathResults.results);
      findings.push(...pathResults.findings);
      filesProcessed += pathResults.filesProcessed;
    }

    const endTime = performance.now();

    // Format output
    const output = {
      success: true,
      files: filesProcessed,
      findings,
      summary: {
        critical: findings.filter((f: any) => f.severity === 'critical').length,
        high: findings.filter((f: any) => f.severity === 'high').length,
        medium: findings.filter((f: any) => f.severity === 'medium').length,
        low: findings.filter((f: any) => f.severity === 'low').length
      },
      duration: endTime - startTime
    };

    // Output results
    const formatted = formatOutput(output, options.format as any);
    
    if (options.output) {
      const fs = await import('fs/promises');
      await fs.writeFile(options.output, formatted);
      console.log(chalk.green(`Results written to ${options.output}`));
    } else {
      console.log(formatted);
    }

    // Exit with error code if critical issues found
    if (output.summary.critical > 0) {
      process.exit(1);
    }
  });

/**
 * Process a file path (file or directory)
 */
async function processPath(
  path: string,
  analyzer: SecurityAnalyzer,
  rules: string[],
  exclude: string[]
): Promise<{ results: any[]; findings: any[]; filesProcessed: number }> {
  const stats = statSync(path);
  
  if (stats.isDirectory()) {
    const files = readdirSync(path);
    const results = [];
    const allFindings = [];
    let fileCount = 0;
    
    for (const file of files) {
      const filePath = join(path, file);
      const fileStats = statSync(filePath);
      
      if (fileStats.isDirectory()) {
        const subResults = await processPath(filePath, analyzer, rules, exclude);
        results.push(...subResults.results);
        allFindings.push(...subResults.findings);
        fileCount += subResults.filesProcessed;
      } else if (isSourceFile(filePath)) {
        const content = readFileSync(filePath, 'utf-8');
        const result = analyzer.analyze({
          filepath: filePath,
          sourceCode: content,
          rules,
          exclude
        });
        results.push(result);
        allFindings.push(...result.findings);
        fileCount++;
      }
    }
    
    return { results, findings: allFindings, filesProcessed: fileCount };
  } else if (isSourceFile(path)) {
    const content = readFileSync(path, 'utf-8');
    const result = analyzer.analyze({
      filepath: path,
      sourceCode: content,
      rules,
      exclude
    });
    return { results: [result], findings: result.findings, filesProcessed: 1 };
  }
  
  return { results: [], findings: [], filesProcessed: 0 };
}

/**
 * Check if file is a source file
 */
function isSourceFile(path: string): boolean {
  const ext = extname(path);
  return ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'].includes(ext);
}

program.parse();