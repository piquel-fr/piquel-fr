import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { signedUp, withPasskeys } from './helpers';

// A command that starts a recovery of the account named by the arguments appended
// to it, e.g. `just auth user recover` or `piquelctl preview exec … -- auth-service
// user recover`.
const recover = process.env.E2E_RECOVER;

/** Runs against a deployment whose CLI the test can run, such as a preview. */
test('a recovery link adds a passkey, and the owner undoes it with an older one', async ({
  browser
}) => {
  test.skip(!recover, 'Set E2E_RECOVER to run the recovery test.');
  const handle = `recovery-${Date.now().toString(36)}`;
  const owner = await signedUp(browser, handle);

  // Support starts a recovery, which signs the owner out everywhere and prints the
  // link. Without a terminal, the command needs `--yes`.
  const printed = execFileSync(
    'sh',
    ['-c', `${recover ?? ''} ${handle} --reason 'Browser test' --yes`],
    { encoding: 'utf8' }
  );
  const link = /https?:\/\/\S+\/recover#token=\S+/.exec(printed)?.[0];
  if (!link) throw new Error('The command printed no recovery link.');

  // Another browser uses the link: its form posts the token from the fragment, and
  // the page that answers names the account and makes the passkey.
  const recovering = await withPasskeys(browser);
  await recovering.goto(link);
  await recovering.getByRole('button', { name: 'Continue', exact: true }).click();
  await expect(recovering.getByText(`Add a passkey to @${handle}`)).toBeVisible();
  await recovering.getByLabel('Passkey name', { exact: true }).fill('Recovered passkey');
  await recovering.getByRole('button', { name: 'Create a passkey', exact: true }).click();
  await expect(recovering).toHaveURL('/settings');
  await expect(
    recovering.getByText('Your account is recovered. Your new passkey signs you in.')
  ).toBeVisible();
  await expect(
    recovering.getByText(/the passkey the recovery added signs in but can.t confirm changes/)
  ).toBeVisible();
  // Answering the question hides it for this session, across page loads, and gives
  // the focus to the page's heading. The passkey script, which shows it, has run once
  // the page has loaded.
  const itWasMe = recovering.getByRole('button', { name: 'Yes, it was me', exact: true });
  await itWasMe.click();
  await expect(itWasMe).toBeHidden();
  await expect(recovering.getByRole('heading', { level: 1 })).toBeFocused();
  await recovering.reload();
  await expect(itWasMe).toBeHidden();

  // The owner signs in again with the passkey from before the recovery. Settings
  // ask too, and lead to the undo page, whose form posts the recovery's ID from
  // the fragment.
  await owner.goto('/login');
  await owner.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await expect(owner).toHaveURL('/settings');
  await owner.getByRole('link', { name: 'No, undo it', exact: true }).click();
  await expect(owner).toHaveURL(/\/recover\/undo#recovery=/);
  await owner.getByRole('button', { name: 'Continue', exact: true }).click();
  await owner.getByRole('button', { name: 'Undo it with a passkey', exact: true }).click();
  await expect(owner).toHaveURL('/settings');
  await expect(
    owner.getByText(
      'The recovery is undone. Its link no longer works, and if it was used, its passkey is removed, every device is signed out, and apps ask for access again.'
    )
  ).toBeVisible();
  await expect(owner.getByText('1 registered', { exact: true })).toBeVisible();

  // The undo ended every session, and signed in only the browser that undid it.
  await recovering.reload();
  await expect(recovering.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible();
});
