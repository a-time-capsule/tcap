import { createContainer, unpackContainer, computeHash } from './src/index';

async function test() {
  console.log('🚀 Starting TCAP Library Tests...');

  const password = 'super-secret-password';
  const files = [
    {
      name: 'hello.txt',
      type: 'text/plain',
      data: new TextEncoder().encode('Hello, Time Capsule!')
    },
    {
      name: 'secret.json',
      type: 'application/json',
      data: new TextEncoder().encode(JSON.stringify({ secret: 42 }))
    }
  ];

  try {
    // 1. Create Container
    console.log('📦 Creating container...');
    const container = await createContainer(files, password);
    console.log(`✅ Container created. Size: ${container.byteLength} bytes`);

    // 2. Compute Hash
    const hash = await computeHash(container);
    console.log(`🔒 Container Hash: ${hash}`);

    // 3. Unpack Container
    console.log('🔓 Unpacking container...');
    const unpackedFiles = await unpackContainer(container, password);
    
    // 4. Verify results
    if (unpackedFiles.length !== files.length) {
      throw new Error('File count mismatch');
    }

    for (let i = 0; i < files.length; i++) {
      const original = files[i];
      const unpacked = unpackedFiles.find(f => f.name === original.name);
      
      if (!unpacked) throw new Error(`File ${original.name} not found in unpacked result`);
      
      const originalText = new TextDecoder().decode(original.data);
      const unpackedText = new TextDecoder().decode(unpacked.data);
      
      if (originalText !== unpackedText) {
        throw new Error(`Content mismatch for ${original.name}`);
      }
      console.log(`✅ File verified: ${original.name}`);
    }

    console.log('🎉 All TCAP tests passed successfully!');
  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
}

test();
