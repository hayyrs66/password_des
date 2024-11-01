/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
	theme: {
		extend: {
			colors:{
				'primary': '#3ecf8e',
				'primary-light': '#157e52',
				'primary-dark': '#1b583d',
				'green': '#067245',
				'green-light': '#157e52',
				'background': '#0a0a0a'
			}
		},
	},
	plugins: [],
}
