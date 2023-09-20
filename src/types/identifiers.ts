export interface CompositeKeyConfig {
  fields: string[];
  separator?: string;
}

export interface IdentifierConfig {
  userIdField?: string | string[];
  userIdPath?: string;
  sessionIdPath?: string;
  extractIdentifiers?: (tokenData: unknown) => ExtractedIdentifiers;
  compositeKey?: CompositeKeyConfig;
  fallbackChain?: string[];
}

export interface ExtractedIdentifiers {
  userId?: string;
  sessionId?: string;
  jti?: string;
  compositeKey?: string;
  metadata?: Record<string, unknown>;
}

export type IdentifierExtractionResult =
  | { success: true; identifiers: ExtractedIdentifiers }
  | { success: false; error: string };

export type PathValidationStatus = 'valid' | 'invalid' | 'empty' | 'missing';

export interface PathValidationResult {
  path: string;
  status: PathValidationStatus;
  value?: unknown;
  error?: string;
}

export type PathValidationResults = PathValidationResult[];
