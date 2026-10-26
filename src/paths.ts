import { realpathSync } from "node:fs";
import path from "node:path";

/**
 * True only for a plain repository-relative spelling. Absolute, drive-qualified, rooted, UNC (`\\host\share`) and
 * device (`\\?\`) paths are rejected on every platform before any filesystem call: on Windows, resolving a UNC path
 * makes an outbound SMB connection, which can leak the operator's NTLM credentials or stall the synchronous server.
 */
export function isRepoRelative(file: string): boolean {
  return !path.posix.isAbsolute(file) && !path.win32.isAbsolute(file) && !/^[\\/]/.test(file) && !/^[A-Za-z]:/.test(file);
}

/**
 * Resolves `target` against `root` and refuses anything that escapes it (including via symlinks).
 * `.native` returns the canonical on-disk name, so Windows 8.3 short names and case variants cannot hide a file's real name.
 */
export function resolveInside(root: string, target: string): string {
  const realRoot = realpathSync.native(root);
  const real = realpathSync.native(path.resolve(realRoot, target));
  const rel = path.relative(realRoot, real);
  if (rel === "" || rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    throw new Error("path is outside repo_root");
  }
  return real;
}
