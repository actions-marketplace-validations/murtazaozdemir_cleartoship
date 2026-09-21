import { dependencyScanner } from './dependencies.js';
import { serverActionsScanner } from './server-actions.js';
import { rlsScanner } from './rls.js';
import { agentLogicScanner } from './agent-logic.js';
import { secretsScanner } from './secrets.js';
import { communityScanner } from './community.js';
import { logicScanner } from './logic.js';
import type { Scanner } from '../types.js';

/**
 * Every scanner is compiled in. Nothing here is loaded by package name at run
 * time: a scan that imports whatever module of a given name it finds beside it runs
 * a stranger's code, and the project being scanned is where that module would come
 * from.
 */
export const SCANNERS: Scanner[] = [
  dependencyScanner,
  serverActionsScanner,
  rlsScanner,
  secretsScanner,
  logicScanner,
  agentLogicScanner,
  communityScanner,
];

export {
  dependencyScanner,
  serverActionsScanner,
  rlsScanner,
  agentLogicScanner,
  secretsScanner,
  communityScanner,
  logicScanner,
};
