export default {
    preset: 'ts-jest',
    testEnvironment: 'node',
    extensionsToTreatAsEsm: ['.ts'],
    rootDir: './',
    coverageDirectory: './coverage',
    testMatch: ['<rootDir>/tests/**/*.test.ts'],
    testPathIgnorePatterns: ['node_modules'],
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1',
    },
    transform: {
        '^.+\\.tsx?$': ['ts-jest', { useESM: true }],
    },
}; 
