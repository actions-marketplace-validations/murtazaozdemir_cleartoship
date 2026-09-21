import { dependencyScanner } from './dependencies.js';
import { secretsScanner } from './secrets.js';
import { communityScanner } from './community.js';
import { logicScanner } from './logic.js';
import type { Scanner } from '../types.js';

/**
 * The RLS suite (Supabase/Postgres Row Level Security), the Server Actions
 * suite (Next.js Server Actions & Route Handlers) and the LLM/agent risk
 * scanner live in the private `cleartoship-rules-pro` repository and are not part
 * of this build. Nothing here loads them: scanners are compiled in, never found
 * by package name at run time.
 */
export const SCANNERS: Scanner[] = [
  dependencyScanner,
  secretsScanner,
  logicScanner,
  communityScanner,
];

export {
  dependencyScanner,
  secretsScanner,
  communityScanner,
  logicScanner,
};
