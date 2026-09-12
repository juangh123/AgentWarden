import * as path from 'node:path';
import { chalk } from './chalk.ts';
import type { ScanResult } from '../rules/types.ts';
import { readPackageVersion } from '../version.ts';
import {
  toReportScanResult,
  toReportScanResults,
  type ReportOptions,
} from './redaction.ts';

export type ReportFormat = 'pretty' | 'json' | 'sarif';
export { toReportScanResult, toReportScanResults, redactText } from './redaction.ts';
export type { ReportOptions } from './redaction.ts';

export function renderScanReport(
  result: ScanResult,
  format: ReportFormat = 'pretty',
  options: ReportOptions = {},
): void {
  renderScanReports([result], format, options);
}

function toArtifactUri(filePath: string): string {
  const rel = path.isAbsolute(filePath) ? path.relative(process.cwd(), filePath) : filePath;
  const uri = (rel && !rel.startsWith('..') ? rel : filePath).replace(/\\/g, '/');
  return uri || 'unknown';
}

export function buildSarifReport(results: ScanResult[], options: ReportOptions = {}) {
  const reportResults = toReportScanResults(results, options);
  const allFindings = reportResults.flatMap(r => r.findings);
  const ruleIds = Array.from(new Set(allFindings.map(f => f.ruleId)));
  const ruleIndexById = new Map(ruleIds.map((id, index) => [id, index]));
  const levelFor = (severity: string): 'error' | 'warning' | 'note' => {
    if (severity === 'critical' || severity === 'high') return 'error';
    if (severity === 'medium') return 'warning';
    return 'note';
  };

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'AgentWarden',
            informationUri: 'https://github.com/juangh123/AgentWarden',
            version: readPackageVersion(),
            rules: ruleIds.map(id => {
              const sample = allFindings.find(f => f.ruleId === id);
              return {
                id,
                name: sample?.title || id,
                shortDescription: { text: sample?.title || id },
                fullDescription: { text: sample?.description || '' },
                defaultConfiguration: {
                  level: levelFor(sample?.severity || 'warning'),
                },
                help: { text: sample?.suggestion || '' },
                properties: {
                  category: sample?.category || '',
                  severity: sample?.severity || '',
                },
              };
            })
          }
        },
        results: reportResults.flatMap(result => {
          const uri = toArtifactUri(result.filePath);
          return result.findings.map(finding => ({
            ruleId: finding.ruleId,
            ruleIndex: ruleIndexById.get(finding.ruleId) ?? 0,
            level: levelFor(finding.severity),
            message: { text: `${finding.description} (Category: ${finding.category})` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri },
                  region: {
                    startLine: Math.max(1, finding.line || 1),
                    snippet: { text: finding.snippet || '' },
                  },
                },
              },
            ],
          }));
        }),
      },
    ],
  };
}

export function renderScanReports(
  results: ScanResult[],
  format: ReportFormat = 'pretty',
  options: ReportOptions = {},
): void {
  if (format === 'json') {
    const reportResults = toReportScanResults(results, options);
    if (reportResults.length === 1) {
      console.log(JSON.stringify(reportResults[0], null, 2));
    } else {
      console.log(JSON.stringify({
        totalScanned: reportResults.length,
        passedCount: reportResults.filter(r => r.passed).length,
        failedCount: reportResults.filter(r => !r.passed).length,
        results: reportResults
      }, null, 2));
    }
    return;
  }

  if (format === 'sarif') {
    console.log(JSON.stringify(buildSarifReport(results, options), null, 2));
    return;
  }

  const reportResults = toReportScanResults(results, options);

  // Pretty terminal output
  for (const result of reportResults) {
    console.log('\n' + chalk.bold.cyan('🛡️  AgentWarden Security Scan Report'));
    console.log(chalk.gray('═'.repeat(60)));
    console.log(`• Skill Name:   ${chalk.bold.white(result.parsedSkill.name)}`);
    console.log(`• Description:  ${chalk.gray(result.parsedSkill.description)}`);
    console.log(`• File Path:    ${chalk.gray(result.filePath)}`);
    console.log(`• SHA256:       ${chalk.gray(result.sha256.slice(0, 16) + '...')}`);
    if (result.baseline) {
      const expiredLabel = result.baseline.expired
        ? chalk.red.bold('EXPIRED') + ', '
        : '';
      const expiryLabel = result.baseline.expiresAt
        ? `, expires ${result.baseline.expiresAt}`
        : '';
      const ownerLabel = result.baseline.owner
        ? `, owner ${result.baseline.owner}`
        : '';
      console.log(
        `• Baseline:     ${chalk.gray(result.baseline.path)} ` +
          `(${expiredLabel}${chalk.yellow(String(result.baseline.suppressed))} accepted, ` +
          `${chalk.gray(String(result.baseline.unmatched) + ' unmatched')}${expiryLabel}${ownerLabel})`,
      );
    }

    const scoreColor = result.score >= 80 ? chalk.green : result.score >= 60 ? chalk.yellow : chalk.red;
    console.log(`• Safety Score: ${scoreColor(result.score.toString() + '/100')}`);
    console.log(chalk.gray('═'.repeat(60)));

    if (result.findings.length === 0) {
      if (result.baseline?.expired) {
        console.log(chalk.yellow.bold('\n⚠️  [WARNING] The configured baseline has expired; current findings are no longer suppressed.\n'));
      }
      if (result.baseline && result.baseline.suppressed > 0) {
        console.log(
          chalk.green.bold(
            `\n✅ [PASS] No new findings; ${result.baseline.suppressed} baseline finding(s) were accepted.\n`,
          ),
        );
      } else {
        console.log(chalk.green.bold('\n✅ [PASS] No security vulnerabilities or prompt injection detected!\n'));
      }
      continue;
    }

    console.log(`\nFound ${chalk.bold.red(result.findings.length.toString())} security issues:`);
    if (result.baseline && result.baseline.suppressed > 0) {
      console.log(chalk.gray(`Baseline accepted ${result.baseline.suppressed} existing finding(s).`));
    }

    result.findings.forEach((finding, idx) => {
      const sevBadge =
        finding.severity === 'critical'
          ? chalk.bgRed.black(' CRITICAL ')
          : finding.severity === 'high'
          ? chalk.red(' HIGH ')
          : finding.severity === 'medium'
          ? chalk.yellow(' MEDIUM ')
          : finding.severity === 'low'
          ? chalk.bgBlue.black(' LOW ')
          : chalk.gray(` ${finding.severity.toUpperCase()} `);

      console.log(`\n${idx + 1}. ${sevBadge} ${chalk.bold.white(finding.title)} (${chalk.gray(finding.ruleId)})`);
      console.log(`   ${finding.description}`);
      if (finding.line) {
        console.log(`   Line: ${chalk.yellow(finding.line.toString())}`);
      }
      if (finding.snippet) {
        console.log(`   Snippet: ${chalk.gray(finding.snippet)}`);
      }
      if (finding.suggestion) {
        console.log(`   ${chalk.green('💡 Remediation:')} ${finding.suggestion}`);
      }
    });

    console.log(chalk.gray('\n' + '─'.repeat(60)));
    if (!result.passed) {
      console.log(chalk.red.bold('❌ [BLOCKED] Skill security check failed! Risk severity threshold exceeded.\n'));
    } else {
      console.log(chalk.yellow.bold('⚠️  [WARNING] Warnings found, but within tolerable policy threshold.\n'));
    }
  }

  if (reportResults.length > 1) {
    const totalFailed = reportResults.filter(r => !r.passed).length;
    console.log(chalk.gray('═'.repeat(60)));
    console.log(chalk.bold(`Scan Summary: ${reportResults.length} skills scanned, ${reportResults.length - totalFailed} passed, ${totalFailed} blocked.`));
    console.log(chalk.gray('═'.repeat(60)) + '\n');
  }
}
