/**
 * Locale-independent string comparison (UTF-16 code unit order).
 *
 * `String.prototype.localeCompare` depends on the host's ICU data and locale,
 * so the same input could sort differently across machines and produce
 * unstable lockfiles, baselines, SBOM documents, and report ordering. Every
 * ordering that ends up in an artifact must use this comparator instead.
 */
export function compareStrings(left: string, right: string): number {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}
