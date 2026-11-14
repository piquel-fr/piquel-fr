/**
 * Runs the OpenID conformance suite against auth, playing the browser's part in
 * Chromium with a virtual passkey, since the suite's own browser cannot run
 * WebAuthn. It registers the suite's clients through the deployment's CLI, signs
 * an account up, runs every plan in plans.json through the suite's API, and
 * compares each test's result with expected.json. `run.sh` starts it; README.md
 * describes the environment it reads.
 */
import {
  chromium,
  request,
  type APIRequestContext,
  type Locator,
  type Page
} from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { mailed } from '../browser/helpers.ts';

/** The suite's address, which docker-compose.yml gives it. */
const suiteUrl = 'https://localhost:8443';
/** The name the suite gives this deployment in its callback URLs. */
const alias = 'sourceorigin';
/** How long one test may take, its waits included, before it counts as `UNKNOWN`. */
const testTimeout = 5 * 60_000;

/** A test's outcome, as the suite reports it. `UNKNOWN`: the test never finished. */
type Result = 'PASSED' | 'FAILED' | 'WARNING' | 'REVIEW' | 'SKIPPED' | 'UNKNOWN';

/** A known deviation: the result a test gives today, why, and the issue fixing it. */
type Expectation = { result: Exclude<Result, 'PASSED' | 'UNKNOWN'>; reason: string; issue: string };

/**
 * A plan to run, with its variant, from plans.json. A `backchannel` plan's client
 * receives back-channel logout tokens, which no other plan expects. It runs only
 * against a local auth: the tokens must reach the suite on this machine, which a
 * preview can't.
 */
type Plan = { plan: string; variant: Record<string, string>; backchannel?: boolean };

/** A suite client's registration and secret. */
type Client = { client_id: string; client_secret: string };

/** What the suite wants the browser to do for a test. */
type BrowserState = {
  urlsWithMethod: { url: string; method: string }[];
  uploadsRequired?: number;
};

/** Reads a required environment variable. */
function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set; run the suite with \`just conformance\`.`);
  return value;
}

const authUrl = required('CONFORMANCE_AUTH_URL').replace(/\/$/, '');
const output = required('CONFORMANCE_OUTPUT');
const only = process.env.CONFORMANCE_TESTS?.split(',').filter(Boolean);
/** Whether `run.sh` started auth on this machine. */
const local = Boolean(process.env.CONFORMANCE_LOCAL);

/** The suite's REST API. */
class Suite {
  private readonly api: APIRequestContext;

  private constructor(api: APIRequestContext) {
    this.api = api;
  }

  /** Connects once the suite answers, which takes it a minute after starting. */
  static async connect(): Promise<Suite> {
    // The suite serves its own self-signed certificate.
    const api = await request.newContext({ baseURL: suiteUrl, ignoreHTTPSErrors: true });
    for (let attempt = 0; attempt < 120; attempt++) {
      const ready = await api.get('/api/plan?length=1').catch(() => undefined);
      if (ready?.ok()) return new Suite(api);
      await sleep(2_000);
    }
    throw new Error(`The suite did not start at ${suiteUrl}.`);
  }

  /** Sends a request to `path` and reads its JSON answer, failing on an error status. */
  private async call<T>(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    options: { params?: Record<string, string>; data?: string; type?: string } = {}
  ): Promise<T> {
    const response = await this.api.fetch(path, {
      method,
      params: options.params,
      data: options.data,
      headers: { 'content-type': options.type ?? 'application/json' }
    });
    if (!response.ok()) {
      throw new Error(`${method} ${path}: ${String(response.status())} ${await response.text()}`);
    }
    const body = await response.text();
    return (body ? JSON.parse(body) : undefined) as T;
  }

  /** Creates `plan` with `config`, answering its ID and its tests. */
  createPlan(
    plan: Plan,
    config: object
  ): Promise<{ id: string; modules: { testModule: string; variant?: object }[] }> {
    return this.call('POST', '/api/plan', {
      params: { planName: plan.plan, variant: JSON.stringify(plan.variant) },
      data: JSON.stringify(config)
    });
  }

  /** Starts `test` of the plan `planId`, answering the test's ID. */
  async startTest(planId: string, test: string, variant?: object): Promise<string> {
    const params: Record<string, string> = { test, plan: planId };
    if (variant) params.variant = JSON.stringify(variant);
    return (await this.call<{ id: string }>('POST', '/api/runner', { params })).id;
  }

  /** The test's status and, once it finished, its result. */
  info(id: string): Promise<{ status: string; result?: Result }> {
    return this.call('GET', `/api/info/${id}`);
  }

  /** What the test found wrong, or wants a person to review: one line each. */
  async findings(id: string): Promise<string[]> {
    const log = await this.call<{ result?: string; src?: string; msg?: string }[]>(
      'GET',
      `/api/log/${id}`
    );
    return log
      .filter(({ result }) => result && ['FAILURE', 'WARNING', 'REVIEW'].includes(result))
      .map(({ result = '', src = '', msg = '' }) => `${result} ${src}: ${msg}`);
  }

  /** What the test waits for the browser to do. */
  async browser(id: string): Promise<BrowserState> {
    return (await this.call<{ browser: BrowserState }>('GET', `/api/runner/${id}`)).browser;
  }

  /** Tells the suite the browser went to `url`. */
  async visited(id: string, url: string): Promise<void> {
    await this.call('POST', `/api/runner/browser/${id}/visit`, { params: { url } });
  }

  /** The screenshots the test asks for and doesn't have yet, by placeholder. */
  async placeholders(id: string): Promise<string[]> {
    const images = await this.call<{ upload?: string }[]>('GET', `/api/log/${id}/images`);
    return images.flatMap((image) => (image.upload ? [image.upload] : []));
  }

  /** Gives the test the screenshot `png` for `placeholder`. */
  async upload(id: string, placeholder: string, png: Buffer): Promise<void> {
    await this.call('POST', `/api/log/${id}/images/${placeholder}`, {
      data: `data:image/png;base64,${png.toString('base64')}`,
      type: 'text/plain'
    });
  }

  /** Stops a test that ran out of time. */
  async stop(id: string): Promise<void> {
    await this.call('DELETE', `/api/runner/${id}`).catch(() => undefined);
  }

  /** Saves the plan's logs, as the suite exports them, to `path`. */
  async export(planId: string, path: string): Promise<void> {
    const response = await this.api.get(`/api/plan/export/${planId}`);
    if (response.ok()) writeFileSync(path, await response.body());
  }
}

/** The deployment's CLI, run by the command in `CONFORMANCE_CLI`. */
class Deployment {
  private readonly command: string[];

  constructor(command: string) {
    this.command = command.split(' ').filter(Boolean);
  }

  /** Runs `args` and answers the JSON result. */
  private run(...args: string[]): unknown {
    const [program, ...given] = this.command;
    const out = execFileSync(program, [...given, '--json', ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });
    // A change with nothing to show prints nothing.
    return out.trim() ? JSON.parse(out) : undefined;
  }

  /** Runs `args`, a change, which the deployment records with its reason. */
  private change(...args: string[]): unknown {
    return this.run(...args, '--reason', 'OpenID conformance suite');
  }

  /**
   * A new signup link. With `mail`, the Mailpit receiving the deployment's
   * email, it is mailed to a new address, which the account then starts with,
   * verified, so the `email` scope has claims to release.
   */
  async invite(mail: string | undefined): Promise<string> {
    if (!mail) return (this.change('invite', 'create') as { link: string }).link;
    const address = `conformance-${Date.now().toString(36)}@example.com`;
    this.change('invite', 'create', '--email', address);
    return mailed(address, /https?:\/\/\S+\/register\?invitation=[\w-]+/, mail);
  }

  /** Gives the account `handle` the display name `name`, which `profile` releases. */
  name(handle: string, name: string): void {
    this.change('account', handle, 'name', 'set', name);
  }

  /**
   * Registers `id`, a confidential client whose browser returns to the suite,
   * and which receives back-channel logout tokens there if `backchannel`, unless
   * an earlier run did, and answers a new secret.
   */
  client(id: string, name: string, backchannel = false): Client {
    const test = `${suiteUrl}/test/a/${alias}`;
    const registration = [
      '--redirect-uri',
      `${test}/callback`,
      '--post-logout-uri',
      `${test}/post_logout_redirect`
    ];
    if (backchannel) registration.push('--backchannel-logout-uri', `${test}/backchannel_logout`);
    let exists = true;
    try {
      this.run('client', 'show', id);
    } catch {
      exists = false;
    }
    if (!exists) {
      const created = this.change(
        'client',
        'create',
        id,
        '--name',
        name,
        '--confidential',
        ...registration
      ) as { secret: string };
      return { client_id: id, client_secret: created.secret };
    }
    const rotated = this.change('client', 'rotate-secret', id, '--grace', '0m', '--yes') as {
      secret: string;
    };
    return { client_id: id, client_secret: rotated.secret };
  }
}

/** Chromium, signed up to auth with a virtual passkey, playing the browser's part. */
class Browser {
  private readonly page: Page;

  private constructor(page: Page) {
    this.page = page;
  }

  /** Launches Chromium with a virtual authenticator, which keeps its passkey for the run. */
  static async launch(): Promise<Browser> {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_EXECUTABLE });
    // The suite's certificate is always self-signed, and so is a local auth's.
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true
      }
    });
    return new Browser(page);
  }

  /** Signs a new account up with the invitation `link`, answering its handle. */
  async signUp(link: string): Promise<string> {
    const handle = `conformance-${Date.now().toString(36)}`;
    await this.page.goto(link);
    await this.page.getByLabel('Handle', { exact: true }).fill(handle);
    await this.page.getByLabel('Passkey name', { exact: true }).fill('Conformance');
    await this.page.getByRole('button', { name: 'Create account with a passkey' }).click();
    await this.page.waitForURL(`${authUrl}/settings`);
    return handle;
  }

  /** Signs out, so each test starts without a session, as the suite expects. */
  async signOut(): Promise<void> {
    await this.page.context().clearCookies();
  }

  /** A screenshot of what the browser shows now. */
  screenshot(): Promise<Buffer> {
    return this.page.screenshot({ fullPage: true });
  }

  /**
   * Goes to `url` with `method`, then does what a person would on each of auth's
   * pages until the browser is back at the suite, or at a page that ends the
   * flow, such as an error. `screenshot` gives the suite the screenshots it
   * asks for: of that last page, or of a sign-in for a pending authorization.
   */
  async visit(url: string, method: string, screenshot: () => Promise<void>): Promise<void> {
    if (method === 'POST') {
      // The suite asks for a form post of the URL's query.
      const target = new URL(url);
      const fields = [...target.searchParams]
        .map(
          ([name, value]) => `<input type="hidden" name="${escape(name)}" value="${escape(value)}">`
        )
        .join('');
      target.search = '';
      await this.page.goto('about:blank');
      await this.page.setContent(
        `<form method="post" action="${escape(target.href)}">${fields}</form>`
      );
      await Promise.all([
        this.page.waitForURL((at) => at.protocol !== 'about:'),
        this.page.locator('form').evaluate((form: HTMLFormElement) => {
          form.submit();
        })
      ]);
      await this.page.waitForLoadState();
    } else {
      await this.page.goto(url);
    }
    for (let step = 0; step < 10; step++) {
      if (new URL(this.page.url()).origin === suiteUrl) {
        // The suite's callback page reports what it received to the suite.
        await this.page.waitForLoadState('networkidle', { timeout: 15_000 }).catch(() => undefined);
        return;
      }
      // Signing in for a pending authorization: a screenshot here shows that auth
      // asked to sign in again. The sign-in page a logout leads to ends the visit.
      const signIn = this.page.getByRole('button', { name: 'Sign in with a passkey', exact: true });
      if (new URL(this.page.url()).searchParams.has('transaction') && (await signIn.isVisible())) {
        await screenshot();
        await this.follow(signIn);
        continue;
      }
      const next = await this.next();
      if (!next || !(await this.follow(next))) {
        await screenshot();
        return;
      }
    }
  }

  /**
   * What a person would press on auth's current page to go on: consent, the link
   * onwards to an address no form may post to, or the confirmation of an
   * application's logout request. None on a page that ends the flow, such as an
   * error.
   */
  private async next(): Promise<Locator | undefined> {
    const actions = [
      this.page.getByRole('button', { name: 'Continue', exact: true }),
      this.page.getByRole('link', { name: 'Continue', exact: true }),
      this.page.getByRole('button', { name: 'Sign out', exact: true })
    ];
    for (const action of actions) if (await action.isVisible()) return action;
    return undefined;
  }

  /** Presses `action`, answering whether the browser went to another page. */
  private async follow(action: Locator): Promise<boolean> {
    const before = this.page.url();
    await action.click();
    await this.page
      .waitForURL((at) => at.href !== before, { timeout: 15_000 })
      .catch(() => undefined);
    await this.page.waitForLoadState();
    return this.page.url() !== before;
  }
}

/** Escapes `value` for an HTML attribute. */
function escape(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

/** Waits `ms` milliseconds. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Runs the suite's test `name` of `planId` to its end, answering its result. */
async function runTest(
  suite: Suite,
  browser: Browser,
  planId: string,
  name: string,
  variant?: object
): Promise<Result> {
  const id = await suite.startTest(planId, name, variant);
  ids.set(name, id);
  await browser.signOut();
  const visited = new Set<string>();
  const screenshots = async () => {
    for (const placeholder of await suite.placeholders(id)) {
      const png = await browser.screenshot();
      writeFileSync(join(output, 'screenshots', `${name}-${placeholder}.png`), png);
      await suite.upload(id, placeholder, png);
    }
  };
  const deadline = Date.now() + testTimeout;
  while (Date.now() < deadline) {
    const { status, result } = await suite.info(id);
    if (status === 'FINISHED' || status === 'INTERRUPTED') return result ?? 'UNKNOWN';
    if (status === 'WAITING') {
      const state = await suite.browser(id);
      const next = state.urlsWithMethod.find(({ url }) => !visited.has(url));
      if (next) {
        visited.add(next.url);
        await suite.visited(id, next.url);
        await browser.visit(next.url, next.method, screenshots);
        continue;
      }
      if (state.uploadsRequired) await screenshots();
    }
    await sleep(500);
  }
  await suite.stop(id);
  return 'UNKNOWN';
}

/** Compares `results` with `expected`, answering every difference. */
function differences(
  results: Map<string, Result>,
  expected: Partial<Record<string, Expectation>>
): string[] {
  const found: string[] = [];
  for (const [test, result] of results) {
    const wanted = expected[test]?.result ?? 'PASSED';
    if (result !== wanted) found.push(`${test}: ${result}, expected ${wanted}`);
  }
  for (const [test, expectation] of Object.entries(expected)) {
    if (!expectation) continue;
    if (
      !/^https:\/\/github\.com\/sourceorigin-dev\/sourceorigin\/issues\/\d+$/.test(
        expectation.issue
      )
    ) {
      found.push(`${test}: expected.json must link the issue that fixes it`);
    }
    if (!only && local && !results.has(test))
      found.push(`${test}: in expected.json, but no plan ran it`);
  }
  return found;
}

const here = import.meta.dirname;
const plans = JSON.parse(readFileSync(join(here, 'plans.json'), 'utf8')) as Plan[];
const expected = JSON.parse(readFileSync(join(here, 'expected.json'), 'utf8')) as Partial<
  Record<string, Expectation>
>;
mkdirSync(join(output, 'screenshots'), { recursive: true });

const deployment = new Deployment(required('CONFORMANCE_CLI'));
const config = {
  alias,
  description: `Origin Auth at ${authUrl}`,
  server: { discoveryUrl: `${authUrl}/.well-known/openid-configuration` },
  client: deployment.client('conformance', 'Conformance suite'),
  client2: deployment.client('conformance-second', 'Conformance suite, second client'),
  client_secret_post: deployment.client('conformance-post', 'Conformance suite, form secret')
};
const backchannelClient = deployment.client(
  'conformance-backchannel',
  'Conformance suite, back-channel logout',
  true
);
const suite = await Suite.connect();
const browser = await Browser.launch();
// Without one, as on a preview, the account has no email address.
const mail = process.env.CONFORMANCE_MAIL_URL;
const handle = await browser.signUp(await deployment.invite(mail));
deployment.name(handle, 'Conformance Tester');
console.log(`Signed up as ${handle}.`);

const results = new Map<string, Result>();
/** Each test's ID in the suite. */
const ids = new Map<string, string>();
for (const plan of plans) {
  if (plan.backchannel && !local) {
    console.log(`${plan.plan}: skipped, as auth is not on this machine`);
    continue;
  }
  const created = await suite.createPlan(
    plan,
    plan.backchannel ? { ...config, client: backchannelClient } : config
  );
  console.log(`${plan.plan}: ${suiteUrl}/plan-detail.html?plan=${created.id}`);
  for (const { testModule, variant } of created.modules) {
    if (only && !only.includes(testModule)) continue;
    const result = await runTest(suite, browser, created.id, testModule, variant);
    results.set(testModule, result);
    console.log(`  ${result.padEnd(8)} ${testModule}`);
    const id = ids.get(testModule);
    if (result !== 'PASSED' && id) {
      for (const finding of await suite.findings(id)) console.log(`             ${finding}`);
    }
  }
  await suite.export(created.id, join(output, `${plan.plan}.zip`));
}
if (!mail) {
  // It checks the account's email claims, which an account without one lacks.
  results.delete('oidcc-scope-email');
  console.log('oidcc-scope-email: not compared, as the account has no email address');
}
writeFileSync(join(output, 'results.json'), JSON.stringify(Object.fromEntries(results), null, 2));

const found = differences(results, expected);
if (found.length > 0) {
  console.error(
    `\n${String(found.length)} results differ from expected.json:\n  ${found.join('\n  ')}`
  );
  process.exit(1);
}
console.log(`\nEvery result matches expected.json.`);
process.exit(0);
