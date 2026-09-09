import * as path from 'node:path';
import { chalk } from './chalk.ts';
import type { ScanResult } from '../rules/types.ts';
import { readPackageVersion } from '../version.ts';

export type ReportFormat = 'pretty' | 'json' | 'sarif';

export function renderScanReport(result: ScanResult, format: ReportFormat = 'pretty'): void {
  renderScanReports([result], format);
}

export function buildSarifReport(results: ScanResult[]) {
  const allFindings = results.flatMap(r => r.findings);
  const ruleIds = Array.from(new Set(allFindings.map(f => f.ruleId)));
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
                  level: sample?.severity === 'critical' || sample?.severity === 'high' ? 'error' : sample?.severity === 'medium' ? 'warning' : 'note'
                }
              };
            })
          }
        },
        results: allFindings.map(f => ({
          ruleId: f.ruleId,
          level: f.severity === 'critical' || f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note',
          message: { text: f.description },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: results.find(r => r.findings.includes(f))?.filePath || 'unknown' },
                region: { startLine: f.line || 1 }
              }
            }
          ]
        }))
      }
    ]
  };
}

export function renderScanReports(results: ScanResult[], format: ReportFormat = 'pretty'): void {
  if (format === 'json') {
    if (results.length === 1) {
      console.log(JSON.stringify(results[0], null, 2));
    } else {
      console.log(JSON.stringify({
        totalScanned: results.length,
        passedCount: results.filter(r => r.passed).length,
        failedCount: results.filter(r => !r.passed).length,
        results
      }, null, 2));
    }
    return;
  }

  if (format === 'sarif') {
    const allFindings = results.flatMap(r => r.findings);
    const ruleIds = Array.from(new Set(allFindings.map(f => f.ruleId)));
    const sarifReport = {
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
                  shortDescription: { text: sample?.title || id },
                  fullDescription: { text: sample?.description || '' },
                  help: { text: sample?.suggestion || '' }
                };
              })
            }
          },
          results: results.flatMap(r => {
            const levelMap: Record<string, string> = {
              critical: 'error',
              high: 'error',
              medium: 'warning',
              low: 'note',
              info: 'note'
            };
            const rel = path.relative(process.cwd(), r.filePath);
            const uri = (rel && !rel.startsWith('..') ? rel : r.filePath).replace(/\\/g, '/');
            return r.findings.map(f => ({
              ruleId: f.ruleId,
              level: levelMap[f.severity] || 'warning',
              message: {
                text: `${f.description} (Category: ${f.category})`
              },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri },
                    region: {
                      startLine: f.line || 1,
                      snippet: {
                        text: f.snippet || ''
                      }
                    }
                  }
                }
              ]
            }));
          })
        }
      ]
    };
    console.log(JSON.stringify(sarifReport, null, 2));
    return;
  }

  // Pretty terminal output
  for (const result of results) {
    console.log('\n' + chalk.bold.cyan('🛡️  AgentWarden Security Scan Report'));
    console.log(chalk.gray('═'.repeat(60)));
    console.log(`• Skill Name:   ${chalk.bold.white(result.parsedSkill.name)}`);
    console.log(`• Description:  ${chalk.gray(result.parsedSkill.description)}`);
    console.log(`• File Path:    ${chalk.gray(result.filePath)}`);
    console.log(`• SHA256:       ${chalk.gray(result.sha256.slice(0, 16) + '...')}`);

    const scoreColor = result.score >= 80 ? chalk.green : result.score >= 60 ? chalk.yellow : chalk.red;
    console.log(`• Safety Score: ${scoreColor(result.score.toString() + '/100')}`);
    console.log(chalk.gray('═'.repeat(60)));

    if (result.findings.length === 0) {
      console.log(chalk.green.bold('\n✅ [PASS] No security vulnerabilities or prompt injection detected!\n'));
      continue;
    }

    console.log(`\nFound ${chalk.bold.red(result.findings.length.toString())} security issues:`);

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

  if (results.length > 1) {
    const totalFailed = results.filter(r => !r.passed).length;
    console.log(chalk.gray('═'.repeat(60)));
    console.log(chalk.bold(`Scan Summary: ${results.length} skills scanned, ${results.length - totalFailed} passed, ${totalFailed} blocked.`));
    console.log(chalk.gray('═'.repeat(60)) + '\n');
  }
}
