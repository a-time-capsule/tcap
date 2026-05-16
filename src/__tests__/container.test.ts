import { describe, it, expect } from 'bun:test';
import { createContainer, unpackContainer, MAGIC_BYTES, VERSION } from '../index';

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
});
