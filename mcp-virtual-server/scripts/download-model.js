/**
 * One-time model download script.
 * Run: node scripts/download-model.js
 *
 * Downloads the quantized all-MiniLM-L6-v2 ONNX model (~23 MB) into
 * mcp-virtual-server/models/ so EmbeddingScanner can load it offline.
 */
'use strict';

const path = require('path');
const { env, pipeline } = require('@xenova/transformers');

const MODEL_DIR = path.join(__dirname, '..', 'models');
const MODEL_ID  = 'Xenova/all-MiniLM-L6-v2';

env.localModelPath     = MODEL_DIR;
env.cacheDir           = MODEL_DIR;   // used as write target on download
env.allowRemoteModels  = true;        // must be true to download
env.allowLocalModels   = true;

(async () => {
  console.log(`Downloading ${MODEL_ID} → ${MODEL_DIR}`);
  console.log('This is a one-time ~23 MB download (quantized ONNX)...\n');

  try {
    // Loading the pipeline is enough to trigger the download and cache.
    const pipe = await pipeline('feature-extraction', MODEL_ID, {
      quantized: true,   // use model_quantized.onnx (~23 MB vs ~86 MB)
    });

    // Quick smoke-test to confirm the model works.
    const out = await pipe('test embedding', { pooling: 'mean', normalize: true });
    console.log(`\nModel loaded OK — embedding dims: ${out.data.length}`);
    console.log(`Saved to: ${MODEL_DIR}`);
    console.log('\nYou can now start the server — the model will load offline.');
  } catch (err) {
    console.error('Download failed:', err.message);
    process.exit(1);
  }
})();
