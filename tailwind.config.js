/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    // Your templ files (both .templ and generated _templ.go files)
    "./internal/views/**/*.{templ,go}",
    "./internal/views/components/**/*.{templ,go}",
    "./internal/views/layouts/**/*.{templ,go}",
    "./internal/views/pages/**/*.{templ,go}",

    // Other Go files that might contain CSS classes
    "./internal/handlers/**/*.go",
    "./internal/routes/**/*.go",
    "./cmd/**/*.go",
    "./server.go",
    "./test.html",
    // Static files
    "./static/**/*.{js,html}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};
