/**
 * Type definitions for secure-audit
 */

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'xss' | 'csrf' | 'privacy' | 'supply-chain' | 'auth' | 'crypto';
  check: (node: any, context: AnalysisContext) => SecurityFinding[];
}

export interface SecurityFinding {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  file: string;
  line: number;
  column: number;
  code: string;
  fix?: FixSuggestion;
  remediation?: string;
}

export interface FixSuggestion {
  description: string;
  code: string;
  position?: {
    start: number;
    end: number;
  };
}

export interface AnalysisContext {
  filename: string;
  sourceCode: string;
  ast: any;
  dependencies: DependencyInfo[];
  config: AuditConfig;
}

export interface DependencyInfo {
  name: string;
  version: string;
  vulnerability?: VulnerabilityInfo;
}

export interface VulnerabilityInfo {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  url: string;
}

export interface AuditConfig {
  rules: string[];
  exclude: string[];
  format: 'json' | 'markdown' | 'sarif' | 'html';
  output?: string;
  fix?: boolean;
  aiEnabled?: boolean;
}

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

export interface RuleCategory {
  [key: string]: SecurityRule[];
}