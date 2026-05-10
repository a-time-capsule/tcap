import { zipSync, unzipSync } from 'fflate';

/**
 * TCAP (Time Capsule Archive Protocol)
 * Version 1 Implementation
 */

export const MAGIC_BYTES = new TextEncoder().encode('TCAP');
export const VERSION = 1;

export interface TcapManifest {
  createdAt: number;
  files: {
    name: string;
    type: string;
    size: number;
    hash: string;
  }[];
}

export interface TcapFile {
  name: string;
  type: string;
  data: Uint8Array;
}

/**
 * Derives a cryptographic key from a password and salt.
 */
export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Creates a TCAP1 container.
 * Structure: [MAGIC(4)] [VERSION(1)] [SALT(16)] [IV_MANIFEST(12)] [MANIFEST_LEN(4)] [ENC_MANIFEST] [IV_PAYLOAD(12)] [ENC_PAYLOAD]
 */
export async function createContainer(files: TcapFile[], password: string): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(password, salt);

  // 1. Prepare manifest
  const manifest: TcapManifest = {
    createdAt: Date.now(),
    files: await Promise.all(files.map(async f => ({
      name: f.name,
      type: f.type,
      size: f.data.byteLength,
      hash: await computeHash(f.data)
    })))
  };

  const manifestData = new TextEncoder().encode(JSON.stringify(manifest));
  const ivManifest = crypto.getRandomValues(new Uint8Array(12));
  const encManifest = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivManifest },
    key,
    manifestData
  ));

  // 2. Prepare payload (Zipped files)
  const zipInput: Record<string, Uint8Array> = {};
  files.forEach(f => {
    zipInput[f.name] = f.data;
  });
  const zippedData = zipSync(zipInput);
  
  const ivPayload = crypto.getRandomValues(new Uint8Array(12));
  const encPayload = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivPayload },
    key,
    zippedData
  ));

  // 3. Assemble container
  const totalSize = 4 + 1 + 16 + 12 + 4 + encManifest.byteLength + 12 + encPayload.byteLength;
  const container = new Uint8Array(totalSize);
  let offset = 0;

  container.set(MAGIC_BYTES, offset); offset += 4;
  container[offset] = VERSION; offset += 1;
  container.set(salt, offset); offset += 16;
  container.set(ivManifest, offset); offset += 12;
  
  const manifestLenView = new DataView(container.buffer);
  manifestLenView.setUint32(offset, encManifest.byteLength, false); offset += 4;
  
  container.set(encManifest, offset); offset += encManifest.byteLength;
  container.set(ivPayload, offset); offset += 12;
  container.set(encPayload, offset);

  return container;
}

/**
 * Unpacks a TCAP1 container.
 */
export async function unpackContainer(container: Uint8Array, password: string): Promise<TcapFile[]> {
  let offset = 0;

  // Verify Magic
  const magic = container.slice(0, 4);
  if (new TextDecoder().decode(magic) !== 'TCAP') throw new Error('Invalid magic bytes');
  offset += 4;

  const version = container[offset];
  if (version !== 1) throw new Error('Unsupported TCAP version');
  offset += 1;

  const salt = container.slice(offset, offset + 16); offset += 16;
  const key = await deriveKey(password, salt);

  const ivManifest = container.slice(offset, offset + 12); offset += 12;
  const manifestLen = new DataView(container.buffer).getUint32(offset, false); offset += 4;
  
  const encManifest = container.slice(offset, offset + manifestLen); offset += manifestLen;
  const manifestData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivManifest },
    key,
    encManifest
  );
  const manifest: TcapManifest = JSON.parse(new TextDecoder().decode(manifestData));

  const ivPayload = container.slice(offset, offset + 12); offset += 12;
  const encPayload = container.slice(offset);
  const zippedData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivPayload },
    key,
    encPayload
  );

  const unzipped = unzipSync(new Uint8Array(zippedData));
  
  return manifest.files.map(f => ({
    name: f.name,
    type: f.type,
    data: unzipped[f.name]
  }));
}

/**
 * Computes SHA-256 hash.
 */
export async function computeHash(data: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
