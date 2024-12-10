import pluginJs from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/** @type {import('eslint').Linter.Config[]} */
export default [
    { files: ['**/*.{js,mjs,cjs,ts}'] },
    {
        languageOptions: {
            globals: Object.fromEntries(
                Object.entries({
                    ...globals.browser,
                    ...globals.node,
                }).map(([key, value]) => [key.trim(), value]),
            ),
        },
    },
    pluginJs.configs.recommended,
    ...tseslint.configs.recommended,
];
