import js from '@eslint/js';
export default [
  js.configs.recommended,
  {
    files: ['**/*.js', '**/*.cjs'],
    languageOptions: {
      ecmaVersion: 2022, sourceType: 'commonjs',
      globals: { process:'readonly', console:'readonly', require:'readonly', module:'readonly', __dirname:'readonly', Buffer:'readonly', setTimeout:'readonly', setInterval:'readonly', URL:'readonly' },
    },
    rules: { 'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }], 'no-console': 'off' },
  },
  {
    files: ['public/**/*.js'],
    languageOptions: {
      sourceType: 'script',
      globals: { window:'readonly', document:'readonly', localStorage:'readonly', fetch:'readonly', FormData:'readonly', URLSearchParams:'readonly', confirm:'readonly', alert:'readonly', console:'readonly', setTimeout:'readonly', clearTimeout:'readonly', location:'readonly', history:'readonly', FileReader:'readonly' },
    },
  },
  { ignores: ['node_modules/**', 'uploads/**'] },
];