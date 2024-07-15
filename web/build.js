import * as esbuild from 'esbuild'
import ElmPlugin from 'esbuild-plugin-elm';

const serve = process.argv.includes('--serve')
const isProd = process.env.NODE_ENV === 'production'

const ctx = await esbuild.context({
  entryPoints: ['index.js', 'index.css'],
  bundle: true,
  outdir: 'static',
  minify: isProd,
  plugins: [
    ElmPlugin({
      debug: !isProd,
      optimize: isProd,
      clearOnWatch: serve,
      verbose: true,
    }),
  ],
})

if (serve) {
  await ctx.watch()
  const { host, port } = await ctx.serve({ host: 'localhost', servedir: 'static' })
  console.log(`Serving at http://${host}:${port}`)
} else {
  await ctx.rebuild()
  await ctx.dispose()
}
