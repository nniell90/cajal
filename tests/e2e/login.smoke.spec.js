const { test, expect } = require('@playwright/test');

test('login page renders expected auth controls', async ({ page }) => {
  await page.goto('/login.html');

  await expect(page).toHaveTitle(/Cajal ICBM Login/i);
  await expect(page.locator('form#loginForm')).toBeVisible();
  await expect(page.locator('input#username')).toBeVisible();
  await expect(page.locator('input#password')).toBeVisible();
  await expect(page.locator('dialog#registerDialog form#registerForm')).toHaveAttribute('novalidate', '');
});

test('unauthenticated root route redirects to login', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveURL(/\/login\.html/);
});
