import { defineConfig } from 'vite';
import { resolve } from 'path';
import dts from 'vite-plugin-dts';

export default defineConfig({
	plugins: [
		dts({
			include: ['./src/**'],
			exclude: ['otp.umd.js']
		})
	],
	build: {
		lib: {
			entry: resolve(__dirname, 'src/index.ts'),
			name: 'Otp',
			fileName: (format) => `otp.${format}.[hash].js`,
			formats: ['umd']
		},
		rollupOptions: {
			external: [],
			output: {
				globals: {}
			}
		}
	}
});
