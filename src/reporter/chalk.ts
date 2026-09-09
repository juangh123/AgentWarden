// Minimal ANSI color helper for zero-dependency CLI execution.
// Honors NO_COLOR and can be toggled at runtime via setColorEnabled().

const autoColor = process.env.NO_COLOR === undefined || process.env.NO_COLOR === '';
let colorEnabled = autoColor && !process.env.FORCE_COLOR;

export function setColorEnabled(enabled: boolean): void {
  colorEnabled = enabled;
}

export function isColorEnabled(): boolean {
  return colorEnabled;
}

const c = (code: string, text: string): string =>
  colorEnabled ? `\x1b[${code}m${text}\x1b[0m` : text;

const cb = (code: string, text: string): string =>
  colorEnabled ? `\x1b[1m\x1b[${code}m${text}\x1b[0m\x1b[22m` : text;

export const chalk = {
  bold: Object.assign((text: string) => (colorEnabled ? `\x1b[1m${text}\x1b[22m` : text), {
    cyan: (text: string) => cb('36', text),
    green: (text: string) => cb('32', text),
    red: (text: string) => cb('31', text),
    white: (text: string) => cb('37', text),
  }),
  gray: (text: string) => c('90', text),
  red: Object.assign((text: string) => c('31', text), {
    bold: (text: string) => cb('31', text),
  }),
  green: Object.assign((text: string) => c('32', text), {
    bold: (text: string) => cb('32', text),
  }),
  yellow: Object.assign((text: string) => c('33', text), {
    bold: (text: string) => cb('33', text),
  }),
  cyan: Object.assign((text: string) => c('36', text), {
    bold: (text: string) => cb('36', text),
  }),
  white: (text: string) => c('37', text),
  bgRed: {
    white: {
      bold: (text: string) => (colorEnabled ? `\x1b[41m\x1b[97m\x1b[1m ${text.trim()} \x1b[22m\x1b[39m\x1b[49m` : text.trim()),
    },
    black: (text: string) => (colorEnabled ? `\x1b[41m\x1b[30m ${text.trim()} \x1b[39m\x1b[49m` : text.trim()),
  },
  bgYellow: {
    black: (text: string) => (colorEnabled ? `\x1b[43m\x1b[30m ${text.trim()} \x1b[39m\x1b[49m` : text.trim()),
  },
  bgBlue: {
    black: (text: string) => (colorEnabled ? `\x1b[44m\x1b[30m ${text.trim()} \x1b[39m\x1b[49m` : text.trim()),
  },
  bgGray: {
    white: (text: string) => (colorEnabled ? `\x1b[100m\x1b[97m ${text.trim()} \x1b[39m\x1b[49m` : text.trim()),
  },
};

export default chalk;
