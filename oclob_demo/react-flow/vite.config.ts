import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
  build: {
    outDir: '../static',
    emptyOutDir: false,
    cssCodeSplit: false,
    lib: {
      entry: 'src/main.tsx',
      name: 'OclobNetworkGraphBundle',
      formats: ['iife'],
      fileName: () => 'react-flow.js',
    },
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) =>
          assetInfo.name?.endsWith('.css') ? 'react-flow.css' : 'react-flow-[name][extname]',
      },
    },
  },
});
