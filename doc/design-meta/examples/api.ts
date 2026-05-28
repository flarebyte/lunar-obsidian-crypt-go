export type TimeUnit = 'seconds' | 'minutes' | 'hours' | 'days' | 'weeks';

export type EncryptionStrength = 'sufficient' | 'good' | 'strong';

export type Expiration = {
  value: number;
  unit: TimeUnit;
};

export type ScopeValue = string | string[];

export type IdPayload = {
  id: string;
  scope?: Record<string, ScopeValue>;
};

export type ProtectedPayload = IdPayload & {
  exp: number;
};

export type TranslucentLizardCypher = {
  kind: 'translucent-lizard';
  title: string;
  secret: Uint8Array;
  altSecret?: Uint8Array;
  strength: EncryptionStrength;
  expiration: Expiration;
  expectedScope?: Record<string, ScopeValue>;
  scopeValidator?: (
    scope: Record<string, ScopeValue>
  ) => true | string;
};

export type Cypher = TranslucentLizardCypher;

export type StoreModel = {
  title: string;
  cyphers: Record<string, Cypher>;
};

export type ValidationError = {
  message: string;
  path: string;
};

export type CryptError =
  | {
      step: 'sign-id/validate-payload' | 'verify-id/validate-payload';
      errors: ValidationError[];
    }
  | {
      step:
        | 'sign-id/sign'
        | 'verify-id/extract-token'
        | 'verify-id/decode-token'
        | 'verify-id/verify-token'
        | 'verify-id/verify-scope'
        | 'verify-id/store'
        | 'sign-id/store';
      message: string;
      finalMessage?: string;
    };

export type Result<T, E> =
  | {status: 'success'; value: T}
  | {status: 'failure'; error: E};

export interface LunarObsidianCryptProtocol {
  signId(prefix: string, payload: IdPayload): Promise<Result<string, CryptError>>;
  verifyId(fullToken: string): Promise<Result<IdPayload, CryptError>>;
  verifyIdByPrefix(
    prefix: string,
    fullToken: string
  ): Promise<Result<IdPayload, CryptError>>;
}
