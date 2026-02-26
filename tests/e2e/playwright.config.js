const path = require('node:path');
const { defineConfig } = require('@playwright/test');

const projectRoot = path.resolve(__dirname, '../..');

module.exports = defineConfig({
  testDir: __dirname,
  timeout: 45_000,
  retries: process.env.CI ? 1 : 0,
  fullyParallel: false,
  use: {
    baseURL: 'http://127.0.0.1:4010',
    headless: true,
    trace: 'retain-on-failure'
  },
  webServer: {
    command: 'node server.js',
    cwd: projectRoot,
    port: 4010,
    timeout: 120_000,
    reuseExistingServer: !process.env.CI,
    env: {
      NODE_ENV: 'test',
      PORT: '4010',
      CAJAL_CONFIG_KEY: 'CI_test_key!Q7xM2nV9pL4tR8kH3dZ1w'
    }
  }
});
