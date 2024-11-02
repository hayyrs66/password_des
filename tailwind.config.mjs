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
				'background': '#0f0f0f',
				'background-light': '#171717'
			},

			gridTemplateColumns:  {
				'dashboard' : '0.5fr 2fr' 
			},
			
			translate: {
				'center-absolute': '50%, -50%'
			}
		},
	},
	plugins: [],
}
