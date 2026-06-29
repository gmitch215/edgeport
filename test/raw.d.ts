// vite ?raw imports load a file's contents as a string (used for key fixtures)
declare module '*?raw' {
	const content: string;
	export default content;
}
