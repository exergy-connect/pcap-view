import {build} from 'esbuild';
import {fileURLToPath} from 'node:url';

const banner = {js: '/*! Copyright © 2026 Exergy ∞ LLC */'};

const root = fileURLToPath(new URL('../', import.meta.url));
const worker = await build({
  absWorkingDir: root,
  entryPoints: ['worker.js'],
  bundle: true,
  minify: true,
  format: 'iife',
  target: 'es2020',
  write: false,
});

const plugins = [{
    name: 'inline-worker',
    setup(builder) {
      builder.onResolve({filter: /\?inline$/}, args => ({path: args.path, namespace: 'inline-worker'}));
      builder.onLoad({filter: /.*/, namespace: 'inline-worker'}, () => ({contents: worker.outputFiles[0].text, loader: 'text'}));
    },
  }];

await build({
  absWorkingDir: root,
  entryPoints: ['library.js'],
  outfile: 'docs/pcap-view.min.js',
  globalName: 'PacketLens',
  bundle: true, minify: true, format: 'iife', target: 'es2020', plugins, banner,
});
await build({
  absWorkingDir: root,
  entryPoints: ['library.js'],
  outfile: 'docs/pcap-view.min.mjs',
  bundle: true, minify: true, format: 'esm', target: 'es2020', plugins, banner,
});

await build({
  absWorkingDir: root,
  entryPoints: ['app.js'],
  outfile: 'docs/app.min.js',
  bundle: true,
  minify: true,
  format: 'iife',
  target: 'es2020',
  plugins,
  banner,
});
