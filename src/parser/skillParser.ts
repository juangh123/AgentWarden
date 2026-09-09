import type { ParsedSkill, CodeBlock  } from '../rules/types.ts';

export function parseSkillMarkdown(content: string, defaultName: string = 'Unnamed-Skill'): ParsedSkill {
  let frontmatter: Record<string, any> = {};
  let body = content;

  // Simple YAML Frontmatter extraction
  const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (fmMatch) {
    const yamlContent = fmMatch[1];
    body = content.slice(fmMatch[0].length);
    yamlContent.split(/\r?\n/).forEach(line => {
      const parts = line.split(':');
      if (parts.length >= 2) {
        const key = parts[0].trim();
        const val = parts.slice(1).join(':').trim().replace(/^['"](.*)['"]$/, '$1');
        frontmatter[key] = val;
      }
    });
  }

  const codeBlocks: CodeBlock[] = [];
  const lines = content.split(/\r?\n/);
  let inCode = false;
  let codeLang = '';
  let currentCode: string[] = [];
  let startLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fenceMatch = line.match(/^```(\w+)?/);

    if (fenceMatch) {
      if (!inCode) {
        inCode = true;
        codeLang = fenceMatch[1] || 'text';
        startLine = i + 1;
        currentCode = [];
      } else {
        inCode = false;
        codeBlocks.push({
          language: codeLang,
          code: currentCode.join('\n'),
          startLine: startLine,
          endLine: i + 1,
        });
      }
    } else if (inCode) {
      currentCode.push(line);
    }
  }

  return {
    name: frontmatter.name || defaultName,
    description: frontmatter.description || '',
    version: frontmatter.version || '0.1.0',
    frontmatter,
    promptText: body,
    codeBlocks,
    rawContent: content,
  };
}
