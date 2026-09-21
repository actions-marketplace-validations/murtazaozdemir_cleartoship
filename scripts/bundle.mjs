/**
 * Builds the standalone distribution: one file, zero runtime dependencies.
 *
 * Why this exists. The npm package declares five runtime dependencies, so
 * installing it — from npmjs.com, from a git URL, or from a release tarball —
 * still needs a registry to resolve them. On the day this package was
 * unpublished and its token rejected, that was the difference between "there is
 * a fallback" and "the fallback also needs npm to be having a good day".
 *
 * The output is a sibling artifact, not a replacement: `npm run build` still
 * produces the module tree that the npm package ships and the tests import.
 * `test/scan.test.js` asserts the two agree finding-for-finding, because a
 * fallback that behaves differently from the tool you tested is not a fallback.
 */
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync, rmSync, copyFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'standalone');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, 'bin'), { recursive: true });

const result = await build({
  entryPoints: [join(root, 'src/cli.ts')],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22.18',
  outfile: join(out, 'bin/cleartoship.mjs'),
  // No `banner` with a shebang here: esbuild preserves the one already at the
  // top of src/cli.ts, and a second on line 2 is a syntax error, not a comment.
  legalComments: 'inline',
  metafile: true,
  // Bundled dependencies keep their licences with them; LICENSES/ and
  // ATTRIBUTION.md ship alongside, as they do in the npm package.
  define: {
    'process.env.CLEARTOSHIP_STANDALONE': '"1"',
    // Stamped in because the raw single file has no package.json beside it to
    // read a version from, and reporting 0.0.0 makes a report unciteable.
    'process.env.CLEARTOSHIP_VERSION': JSON.stringify(pkg.version),
  },
});

// The CLI reads its version from ../package.json relative to the entry file.
// The standalone layout puts that one directory up from bin/, so the manifest
// below has to sit where the running file expects to find it.
writeFileSync(
  join(out, 'package.json'),
  JSON.stringify(
    {
      name: pkg.name,
      version: pkg.version,
      description: pkg.description,
      license: pkg.license,
      type: 'module',
      bin: { cleartoship: 'bin/cleartoship.mjs' },
      // Stated explicitly because the raw single-file copy sits in this same
      // directory for the release step to pick up, and without a `files` list
      // npm packs it too — shipping the 2 MB bundle twice and doubling the
      // download for nothing.
      files: ['bin', 'README.md', 'LICENSE', 'ATTRIBUTION.md', 'SECURITY.md'],
      engines: pkg.engines,
      repository: pkg.repository,
      homepage: pkg.homepage,
      // Deliberately empty. That is the whole point of this artifact.
      dependencies: {},
    },
    null,
    2,
  ) + '\n',
);

for (const file of ['README.md', 'LICENSE', 'ATTRIBUTION.md', 'SECURITY.md']) {
  copyFileSync(join(root, file), join(out, file));
}

// The same file, at the top level, is the artifact for the install path that
// involves no package manager at all: curl it and run it with node. npm 12
// refuses remote-URL and git installs by default (allow-remote/allow-git are
// "none"), so the tarball paths now need an explicit flag — this one does not
// go near npm.
copyFileSync(join(out, 'bin/cleartoship.mjs'), join(out, 'cleartoship.mjs'));

const bytes = Object.values(result.metafile.outputs)[0].bytes;
console.log(`standalone/bin/cleartoship.mjs  ${(bytes / 1024).toFixed(0)} KB, 0 dependencies`);
