import { dependencyScanner } from './dependencies.js';
import { secretsScanner } from './secrets.js';
import { communityScanner } from './community.js';
import { logicScanner } from './logic.js';
import type { Scanner } from '../types.js';

/**
 * The RLS suite (Supabase/Postgres Row Level Security), the Server Actions
 * suite (Next.js Server Actions & Route Handlers) and the LLM/agent risk
 * scanner moved to `cleartoship-rules-pro` — see `src/scanners/optional.ts`
 * for how a licensed install of that package is loaded into a scan.
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
