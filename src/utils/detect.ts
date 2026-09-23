import { join } from 'node:path';
import { exists, safeRead } from './files.js';
import type { FrameworkInfo } from '../types.js';

function hasDep(pkg: any, name: string): boolean {
  if (!pkg) return false;
  return Boolean(
    pkg.dependencies?.[name] ||
      pkg.devDependencies?.[name] ||
      pkg.peerDependencies?.[name],
  );
}

export function detectFramework(root: string, files: string[]): FrameworkInfo {
  let pkg: any = null;
  // Contained: a root `package.json` symlinked outside the repository is not it.
  const raw = safeRead(root, 'package.json');
  if (raw) {
    try {
      pkg = JSON.parse(raw);
    } catch {
      /* malformed package.json is reported by the dependency scanner */
    }
  }

  const hasApp =
    exists(join(root, 'app')) ||
    exists(join(root, 'src/app')) ||
    files.some((f) => /\/(src\/)?app\/.*\/(page|layout|route)\.(t|j)sx?$/.test(f));
  const hasPages =
    exists(join(root, 'pages')) || exists(join(root, 'src/pages'));
  const isNext = hasDep(pkg, 'next') || hasApp || hasPages;

  let nextjs: FrameworkInfo['nextjs'] = null;
  if (isNext) {
    if (hasApp && hasPages) nextjs = 'both';
    else if (hasApp) nextjs = 'app-router';
    else if (hasPages) nextjs = 'pages-router';
    else nextjs = 'app-router';
  }

  const supabase =
    hasDep(pkg, '@supabase/supabase-js') ||
    hasDep(pkg, '@supabase/ssr') ||
    hasDep(pkg, '@supabase/auth-helpers-nextjs') ||
    exists(join(root, 'supabase'));

  // Expo counts: it is React Native underneath, and the mobile rules apply.
  const reactNative =
    hasDep(pkg, 'react-native') ||
    hasDep(pkg, 'expo') ||
    exists(join(root, 'metro.config.js')) ||
    exists(join(root, 'metro.config.ts')) ||
    exists(join(root, 'app.json')) &&
      /\b(expo|react-native)\b/.test(safeRead(root, 'app.json') ?? '');

  const info: FrameworkInfo = {
    nextjs,
    supabase,
    prisma: hasDep(pkg, '@prisma/client') || exists(join(root, 'prisma')),
    drizzle: hasDep(pkg, 'drizzle-orm'),
    clerk: hasDep(pkg, '@clerk/nextjs') || hasDep(pkg, '@clerk/clerk-sdk-node'),
    nextAuth: hasDep(pkg, 'next-auth') || hasDep(pkg, '@auth/core'),
    stripe: hasDep(pkg, 'stripe'),
    python:
      exists(join(root, 'requirements.txt')) ||
      exists(join(root, 'pyproject.toml')),
    reactNative,
    firebase:
      hasDep(pkg, 'firebase') ||
      hasDep(pkg, 'firebase-admin') ||
      hasDep(pkg, '@firebase/app') ||
      exists(join(root, 'firebase.json')),
    describe() {
      const parts: string[] = [];
      if (this.nextjs === 'app-router') parts.push('Next.js (App Router)');
      else if (this.nextjs === 'pages-router') parts.push('Next.js (Pages Router)');
      else if (this.nextjs === 'both') parts.push('Next.js (App + Pages Router)');
      if (this.supabase) parts.push('Supabase');
      if (this.prisma) parts.push('Prisma');
      if (this.drizzle) parts.push('Drizzle');
      if (this.clerk) parts.push('Clerk');
      if (this.nextAuth) parts.push('NextAuth');
      if (this.stripe) parts.push('Stripe');
      if (this.python) parts.push('Python');
      if (this.reactNative) parts.push('React Native');
      if (this.firebase) parts.push('Firebase');
      return parts.length ? parts.join(' + ') : 'generic JavaScript/TypeScript';
    },
  };
  return info;
}
