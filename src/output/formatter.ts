/**
 * Output Formatter Module
 * Supports JSON, Markdown, SARIF, and HTML formats
 */

export interface AuditResult {
  success: boolean;
  files: number;
  findings: SecurityFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  duration: number;
}

export interface SecurityFinding {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  file: string;
  line: number;
  column: number;
  code: string;
  recommendation?: string;
  fix?: FixSuggestion;
}

export interface FixSuggestion {
  description: string;
  code: string;
}

/**
 * Format audit results
 */
export function formatOutput(result: AuditResult, format: 'json' | 'markdown' | 'sarif' | 'html'): string {
  switch (format) {
    case 'json':
      return formatJSON(result);
    case 'markdown':
      return formatMarkdown(result);
    case 'sarif':
      return formatSARIF(result);
    case 'html':
      return formatHTML(result);
    default:
      return formatJSON(result);
  }
}

/**
 * JSON format output
 */
function formatJSON(result: AuditResult): string {
  return JSON.stringify(result, null, 2);
}

/**
 * Markdown format output
 */
function formatMarkdown(result: AuditResult): string {
  const lines: string[] = [];
  
  lines.push('# Security Audit Report');
  lines.push('');
  lines.push(`**Status**: ${result.success ? '✅ Passed' : '❌ Failed'}`);
  lines.push(`**Files**: ${result.files}`);
  lines.push(`**Duration**: ${result.duration.toFixed(2)}ms`);
  lines.push('');
  
  lines.push('## Summary');
  lines.push('');
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Critical | ${result.summary.critical} |`);
  lines.push(`| High | ${result.summary.high} |`);
  lines.push(`| Medium | ${result.summary.medium} |`);
  lines.push(`| Low | ${result.summary.low} |`);
  lines.push('');
  
  if (result.findings.length > 0) {
    lines.push('## Findings');
    lines.push('');
    
    for (const finding of result.findings) {
      lines.push(`### ${finding.ruleId}: ${finding.message}`);
      lines.push('');
      lines.push(`**Severity**: ${finding.severity.toUpperCase()}`);
      lines.push(`**File**: \`${finding.file}\`, Line ${finding.line}`);
      lines.push(`**Code**:`);
      lines.push('```');
      lines.push(finding.code);
      lines.push('```');
      lines.push('');
      
      if (finding.recommendation) {
        lines.push(`**Recommendation**: ${finding.recommendation}`);
        lines.push('');
      }
    }
  }
  
  return lines.join('\n');
}

/**
 * SARIF format output (Static Analysis Results Interchange Format)
 */
function formatSARIF(result: AuditResult): string {
  const sarif: any = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'SecureAudit',
            version: '0.1.0',
            informationUri: 'https://github.com/yourname/secure-audit',
            rules: getRules()
          }
        },
        results: result.findings.map(finding => ({
          ruleId: finding.ruleId,
          level: getSARIFLevel(finding.severity),
          message: {
            text: finding.message
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.file
                },
                region: {
                  startLine: finding.line,
                  startColumn: finding.column
                }
              }
            }
          ],
          properties: {
            code: finding.code,
            recommendation: finding.recommendation
          }
        })),
        automationDetails: {
          description: {
            text: 'Security audit completed'
          }
        }
      }
    ]
  };
  
  return JSON.stringify(sarif, null, 2);
}

/**
 * HTML format output
 */
function formatHTML(result: AuditResult): string {
  const severityColors: Record<string, string> = {
    critical: '#dc3545',
    high: '#fd7e14',
    medium: '#ffc107',
    low: '#28a745'
  };
  
  const lines: string[] = [];
  
  lines.push('<!DOCTYPE html>');
  lines.push('<html lang="en">');
  lines.push('<head>');
  lines.push('  <meta charset="UTF-8">');
  lines.push('  <meta name="viewport" content="width=device-width, initial-scale=1.0">');
  lines.push('  <title>SecureAudit Report</title>');
  lines.push('  <style>');
  linespush('    * { box-sizing: border-box; margin: 0; padding: 0; }');
  lines.push('    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 20px; background: #f5f5f5; }');
  lines.push('    .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }');
  lines.push('    h1 { color: #333; margin-bottom: 20px; }');
  lines.push('    .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }');
  lines.push('    .severity-box { padding: 15px; border-radius: 8px; text-align: center; }');
  lines.push('    .critical { background: #f8d7da; color: #721c24; }');
  lines.push('    .high { background: #fff3cd; color: #856404; }');
  lines.push('    .medium { background: #fff3cd; color: #856404; }');
  lines.push('    .low { background: #d4edda; color: #155724; }');
  lines.push('    .severity-number { font-size: 2em; font-weight: bold; }');
  lines.push('    .severity-label { font-size: 0.8em; text-transform: uppercase; }');
  lines.push('    .finding { border-left: 4px solid #007bff; padding: 15px; margin-bottom: 15px; background: #f8f9fa; }');
  lines.push('    .finding.critical { border-left-color: #dc3545; }');
  lines.push('    .finding.high { border-left-color: #fd7e14; }');
  lines.push('    .finding.medium { border-left-color: #ffc107; }');
  lines.push('    .finding.low { border-left-color: #28a745; }');
  lines.push('    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }');
  lines.push('    .rule-id { font-weight: bold; background: #e9ecef; padding: 5px 10px; border-radius: 4px; }');
  lines.push('    .code { background: #f1f3f4; padding: 10px; border-radius: 4px; font-family: "SFMono-Regular", Consolas, monospace; font-size: 0.9em; }');
  lines.push('    .recommendation { margin-top: 10px; padding: 10px; background: #d1ecf1; border-radius: 4px; }');
  lines.push('  </style>');
  lines.push('</head>');
  lines.push('<body>');
  lines.push('  <div class="container">');
  
  linespush(`    <h1>🔒 Security Audit Report</h1>`);
  
  lines.push('    <div class="summary">');
  lines.push('      <div class="severity-box critical">');
  lines.push(`        <div class="severity-number">${result.summary.critical}</div>`);
  lines.push('        <div class="severity-label">Critical</div>');
  lines.push('      </div>');
  lines.push('      <div class="severity-box high">');
  lines.push(`        <div class="severity-number">${result.summary.high}</div>`);
  lines.push('        <div class="severity-label">High</div>');
  lines.push('      </div>');
  lines.push('      <div class="severity-box medium">');
  lines.push(`        <div class="severity-number">${result.summary.medium}</div>`);
  lines.push('        <div class="severity-label">Medium</div>');
  lines.push('      </div>');
  lines.push('      <div class="severity-box low">');
  lines.push(`        <div class="severity-number">${result.summary.low}</div>`);
  lines.push('        <div class="severity-label">Low</div>');
  lines.push('      </div>');
  lines.push('    </div>');
  
  if (result.findings.length > 0) {
    lines.push('    <h2>Findings</h2>');
    
    for (const finding of result.findings) {
      lines.push(`    <div class="finding ${finding.severity}">`);
      lines.push('      <div class="finding-header">');
      linespush(`        <span class="rule-id">${finding.ruleId}</span>`);
      linespush(`        <span style="color: ${severityColors[finding.severity]}; font-weight: bold;">${finding.severity.toUpperCase()}</span>`);
      lines.push('      </div>');
      linespush(`      <p><strong>File:</strong> ${finding.file}:${finding.line}</p>`);
      linespush(`      <p>${finding.message}</p>`);
      linespush(`      <div class="code">${escapeHtml(finding.code)}</div>`);
      if (finding.recommendation) {
        linespush(`      <div class="recommendation"><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</div>`);
      }
      lines.push('    </div>');
    }
  }
  
  lines.push('  </div>');
  lines.push('</body>');
  lines.push('</html>');
  
  return lines.join('\n');
}

/**
 * Get rule metadata
 */
function getRules(): any[] {
  return [
    {
      id: 'XSS-001',
      shortDescription: { text: 'Unsafe innerHTML assignment' },
      fullDescription: { 
        text: 'Using innerHTML with user content can lead to XSS vulnerabilities'
      },
      defaultConfiguration: { level: 'error' }
    },
    // More rules would be defined here
  ];
}

/**
 * Get SARIF severity level
 */
function getSARIFLevel(severity: string): 'failure' | 'warning' | 'note' {
  switch (severity) {
    case 'critical': return 'failure';
    case 'high': return 'warning';
    case 'medium': return 'warning';
    case 'low': return 'note';
    default: return 'note';
  }
}

/**
 * Escape HTML entities
 */
function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}