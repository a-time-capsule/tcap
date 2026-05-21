import { describe, it, expect, afterEach } from 'bun:test';
import { createContainer, unpackContainer } from '../index';

const originalCrypto = globalThis.crypto;

function stripSubtle() {
  Object.defineProperty(globalThis, 'crypto', {
    value: { getRandomValues: originalCrypto.getRandomValues.bind(originalCrypto) },
    configurable: true,
    writable: true,
  });
}

function restoreCrypto() {
  Object.defineProperty(globalThis, 'crypto', {
    value: originalCrypto,
    configurable: true,
    writable: true,
  });
}

describe('TCAP secure-context guard', () => {
  afterEach(() => restoreCrypto());

  it('createContainer throws a descriptive error when subtle is missing', async () => {
    stripSubtle();
    await expect(
      createContainer([{ name: 'a.txt', type: 'text/plain', data: new Uint8Array([1]) }], 'pw')
    ).rejects.toThrow(/SubtleCrypto unavailable/);
  });

  it('unpackContainer throws a descriptive error when subtle is missing', async () => {
    stripSubtle();
    await expect(unpackContainer(new Uint8Array(64), 'pw')).rejects.toThrow(
      /SubtleCrypto unavailable/
    );
  });
});
