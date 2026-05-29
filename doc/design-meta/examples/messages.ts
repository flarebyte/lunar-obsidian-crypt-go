export const storeExample = {
  title: 'Business ID signing store',
  cyphers: {
    product: {
      kind: 'translucent-lizard',
      title: 'Sign product IDs',
      secret: '<opaque bytes>',
      strength: 'sufficient',
      expiration: {value: 2, unit: 'hours'},
    },
    company: {
      kind: 'translucent-lizard',
      title: 'Sign company IDs',
      secret: '<opaque bytes>',
      altSecret: '<previous opaque bytes>',
      strength: 'strong',
      expiration: {value: 2, unit: 'weeks'},
      expectedScope: {account: 'account890'},
    },
  },
} as const;

export const signRequest = {
  prefix: 'product',
  payload: {
    id: 'product123',
    scope: {account: 'account890'},
  },
} as const;

export const signSuccess = {
  status: 'success',
  value: 'product:<signed-id-token>',
} as const;

export const verifyRequest = {
  fullToken: signSuccess.value,
} as const;

export const verifySuccess = {
  status: 'success',
  value: {
    id: 'product123',
    scope: {account: 'account890'},
  },
} as const;

export const scopeFailure = {
  status: 'failure',
  error: {
    step: 'verify-id/verify-scope',
    message: 'The following fields [account] from the scope did not match the expectations',
  },
} as const;
