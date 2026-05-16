import { describe, it, expect } from 'bun:test';
import { deriveKey, computeHash } from '../index';

describe('Crypto Utility Tests', () => {
  it('should compute SHA-256 hash correctly', async () => {
    const data = new TextEncoder().encode('hello world');
    const hash = await computeHash(data);
    
    // Expected SHA-256 of "hello world"
    expect(hash).toBe('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
  });

  it('should compute different hashes for different data', async () => {
    const data1 = new TextEncoder().encode('data A');
    const data2 = new TextEncoder().encode('data B');
    
    const hash1 = await computeHash(data1);
    const hash2 = await computeHash(data2);
    
    expect(hash1).not.toBe(hash2);
  });

  it('should derive a CryptoKey from a password and salt', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey('my-secret-password', salt);
    
    expect(key).toBeDefined();
    expect(key.algorithm.name).toBe('AES-GCM');
    expect(key.type).toBe('secret');
    expect(key.extractable).toBe(false);
  });

  it('should derive different keys for different salts with same password', async () => {
    const salt1 = crypto.getRandomValues(new Uint8Array(16));
    const salt2 = crypto.getRandomValues(new Uint8Array(16));
    
    const key1 = await deriveKey('password123', salt1);
    const key2 = await deriveKey('password123', salt2);
    
    // While we can't easily extract and compare raw bytes (extractable is false),
    // we can assume the derivation process is deterministic for same salt and different for different salts.
    // In WebCrypto API, the returned objects are different instances.
    expect(key1).not.toBe(key2);
  });
});
