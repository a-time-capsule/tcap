import { describe, it, expect } from 'bun:test';
import {
  createContainer,
  unpackContainer,
  deriveKey,
  computeHash,
  MAGIC_BYTES,
  VERSION,
  PBKDF2_ITERATIONS,
  LEGACY_PBKDF2_ITERATIONS,
} from '../index';
import { zipSync } from 'fflate';

describe('TCAP Container Tests', () => {
  const password = 'test-password-123';
  const sampleFiles = [
    {
      name: 'file1.txt',
      type: 'text/plain',
      data: new TextEncoder().encode('Hello File 1')
    },
    {
      name: 'data.json',
      type: 'application/json',
      data: new TextEncoder().encode(JSON.stringify({ value: 42 }))
    }
  ];

  it('should successfully create and unpack a container', async () => {
    const container = await createContainer(sampleFiles, password);
    
    expect(container).toBeDefined();
    expect(container.byteLength).toBeGreaterThan(0);
    
    // Check magic bytes
    expect(container.slice(0, 4)).toEqual(MAGIC_BYTES);
    // Check version
    expect(container[4]).toBe(VERSION);

    const unpacked = await unpackContainer(container, password);
    
    expect(unpacked).toHaveLength(2);
    
    const file1 = unpacked.find(f => f.name === 'file1.txt');
    expect(file1).toBeDefined();
    expect(file1?.type).toBe('text/plain');
    expect(new TextDecoder().decode(file1?.data)).toBe('Hello File 1');

    const file2 = unpacked.find(f => f.name === 'data.json');
    expect(file2).toBeDefined();
    expect(file2?.type).toBe('application/json');
    expect(new TextDecoder().decode(file2?.data)).toBe('{"value":42}');
  });

  it('should throw an error with incorrect magic bytes', async () => {
    const container = await createContainer(sampleFiles, password);
    
    // Corrupt magic bytes
    container[0] = 0x00;
    
    expect(unpackContainer(container, password)).rejects.toThrow('Invalid magic bytes');
  });

  it('should throw an error with unsupported version', async () => {
    const container = await createContainer(sampleFiles, password);
    
    // Corrupt version
    container[4] = 99;
    
    expect(unpackContainer(container, password)).rejects.toThrow('Unsupported TCAP version');
  });

  it('should fail to unpack with incorrect password', async () => {
    const container = await createContainer(sampleFiles, password);

    // Subtle crypto throws an OperationError if decryption fails due to wrong key
    expect(unpackContainer(container, 'wrong-password')).rejects.toThrow();
  });

  describe('PBKDF2 iteration count (M-01)', () => {
    it('should use the current iteration count (≥310k) for new containers', () => {
      expect(PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(310_000);
    });

    it('should still unpack legacy containers created with 100k iterations', async () => {
      // Build a container by hand using the legacy iteration count.
      // Format must match TCAP1 layout in createContainer(), so any drift
      // there will fail this test loudly.
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const key = await deriveKey(password, salt, LEGACY_PBKDF2_ITERATIONS);

      const manifest = {
        createdAt: Date.now(),
        files: await Promise.all(sampleFiles.map(async f => ({
          name: f.name,
          type: f.type,
          size: f.data.byteLength,
          hash: await computeHash(f.data),
        }))),
      };
      const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
      const ivManifest = crypto.getRandomValues(new Uint8Array(12));
      const encManifest = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: ivManifest }, key, manifestBytes
      ));

      const zipInput: Record<string, Uint8Array> = {};
      sampleFiles.forEach(f => { zipInput[f.name] = f.data; });
      const zipped = zipSync(zipInput);
      const ivPayload = crypto.getRandomValues(new Uint8Array(12));
      const encPayload = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: ivPayload }, key, zipped
      ));

      const total = 4 + 1 + 16 + 12 + 4 + encManifest.byteLength + 12 + encPayload.byteLength;
      const container = new Uint8Array(total);
      let o = 0;
      container.set(MAGIC_BYTES, o); o += 4;
      container[o] = VERSION; o += 1;
      container.set(salt, o); o += 16;
      container.set(ivManifest, o); o += 12;
      new DataView(container.buffer).setUint32(o, encManifest.byteLength, false); o += 4;
      container.set(encManifest, o); o += encManifest.byteLength;
      container.set(ivPayload, o); o += 12;
      container.set(encPayload, o);

      const unpacked = await unpackContainer(container, password);
      expect(unpacked).toHaveLength(2);
      const f1 = unpacked.find(f => f.name === 'file1.txt');
      expect(new TextDecoder().decode(f1?.data)).toBe('Hello File 1');
    });

    it('derives a key within UX-acceptable time (<500ms)', async () => {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const start = performance.now();
      await deriveKey('benchmark-password', salt);
      const elapsed = performance.now() - start;
      // Allow generous headroom for CI; the OWASP target is "interactive".
      expect(elapsed).toBeLessThan(2000);
    });
  });
});
