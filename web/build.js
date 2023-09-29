/*
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

import * as esbuild from 'esbuild';
import ElmPlugin from 'esbuild-plugin-elm';

const watch = process.argv.includes('--watch')
const isProd = process.env.NODE_ENV === 'production'

const ctx = await esbuild.context({
  entryPoints: ['index.js'],
  bundle: true,
  outfile: 'static/index.js',
  minify: isProd,
  plugins: [
    ElmPlugin({
      debug: !isProd,
      optimize: isProd,
      verbose: true,
    }),
  ],
})

if (watch) {
  await ctx.watch();
  // Wait for a keypress to exit
  await new Promise((resolve) => {
    process.stdin.on('data', resolve);
  });
} else {
  await ctx.rebuild();
}

await ctx.dispose();
