/**
 * The search script, which auth's pages and the admin dashboard both load. It
 * exports nothing, and nothing compiles it: auth embeds this file as it is, under
 * a path naming its content, and `tsc` only checks its JSDoc types. Every page
 * works without it.
 *
 * The top bar's search, `form[data-search]`, ranks its results as the user types:
 * - its `<template>` holds every page and setting of the area as an
 *   `a[role=option]`, in a `[data-group]` under its heading, found by its title,
 *   by what it belongs to and by its `data-terms`. While open, its listbox holds
 *   only the groups it shows, and nothing once closed, so no hidden result
 *   stands beside the page's own text. An empty query lists the pages;
 * - a form with `data-suggest` also asks that URL, with `?q=`, for what else the
 *   query finds, such as accounts, as the server ranks them: groups in the same
 *   markup, which replace the last ones it answered;
 * - ArrowUp and ArrowDown choose a result, Enter follows it with a click, so the
 *   dashboard's script still confirms first where a link asks, and Escape
 *   closes the list. Enter without a result submits the form, if it has an
 *   `action`, which then searches by itself: its `[data-all]` result says so;
 * - `/`, or Ctrl or ⌘ with K, focuses it from anywhere on the page. The form is
 *   `hidden` while it needs the script.
 *
 * A live search input, `[data-live]`, refreshes its form's results as the user
 * types: it submits its form in the background, as its form's
 * `[data-live-submit]` button would, if it has one, and swaps in the elements
 * of the answer whose IDs its `data-live` lists. A `GET` form's address follows,
 * so a reload or a shared link shows the same results.
 *
 * A link to a closed disclosure, a `<details>` with an ID, opens it.
 */

/** The results a group shows at most for a query, past which it should narrow. */
const SHOWN = 8;
/** How long typing pauses before a request, in milliseconds. */
const PAUSE = 100;
/** The shortest query the server is asked about: shorter ones match too much. */
const ASKED = 2;
/** An account ID, which the server finds only whole. */
const ID = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
/** How long typing pauses before a live form refreshes, in milliseconds. */
const LIVE_PAUSE = 150;

/**
 * `text` lowercased, without accents, as queries and results compare.
 * @param {string} text
 */
const fold = (text) => text.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();

/**
 * The words of folded `text`.
 * @param {string} text
 */
const words = (text) => text.split(/[^\p{L}\p{N}@]+/u).filter(Boolean);

/**
 * Whether `a` turns into `b` with at most one letter added, removed, changed,
 * or two side by side swapped.
 * @param {string} a
 * @param {string} b
 */
function oneEditApart(a, b) {
  if (Math.abs(a.length - b.length) > 1) return false;
  let start = 0;
  while (start < a.length && a[start] === b[start]) start++;
  const [restA, restB] = [a.slice(start), b.slice(start)];
  return (
    restA.slice(1) === restB.slice(1) ||
    restA.slice(1) === restB ||
    restA === restB.slice(1) ||
    (restA.slice(0, 2) === restB.charAt(1) + restB.charAt(0) && restA.slice(2) === restB.slice(2))
  );
}

/**
 * Whether `token`, four letters or more, is a word of `list`, or the start of
 * one, but for one typo.
 * @param {string[]} list
 * @param {string} token
 */
const nearly = (list, token) =>
  token.length >= 4 &&
  list.some(
    (word) => oneEditApart(token, word) || oneEditApart(token, word.slice(0, token.length))
  );

/**
 * Whether `token`'s letters appear in `text` in order, as in an abbreviation.
 * @param {string} text
 * @param {string} token
 */
function sequence(text, token) {
  let at = 0;
  for (const letter of token) {
    at = text.indexOf(letter, at) + 1;
    if (at === 0) return false;
  }
  return true;
}

/**
 * A result, as it is matched: its folded title and other words.
 * @typedef {{ option: HTMLAnchorElement; title: string; titleWords: string[]; other: string; otherWords: string[]; label: string; order: number }} Entry
 */

/**
 * How well `token` matches `entry`: 0 when it does not.
 * @param {Entry} entry
 * @param {string} token
 */
function tokenScore(entry, token) {
  if (entry.title === token) return 100;
  if (entry.title.startsWith(token)) return 90;
  if (entry.titleWords.some((word) => word.startsWith(token))) return 75;
  if (entry.otherWords.some((word) => word.startsWith(token))) return 55;
  if (entry.title.includes(token)) return 45;
  if (entry.other.includes(token)) return 35;
  if (nearly(entry.titleWords, token)) return 30;
  if (nearly(entry.otherWords, token)) return 20;
  if (token.length >= 2 && sequence(entry.title, token)) return 10;
  return 0;
}

/**
 * How well every token of `tokens` matches `entry`, as the sum of each one's
 * score: 0 when one does not.
 * @param {Entry} entry
 * @param {string[]} tokens
 */
function score(entry, tokens) {
  let total = 0;
  for (const token of tokens) {
    const one = tokenScore(entry, token);
    if (!one) return 0;
    total += one;
  }
  return total;
}

/**
 * Writes `label` into `title`, its parts matching `tokens` marked. Accented
 * titles, whose folded letters do not line up, are written plain.
 * @param {HTMLElement} title
 * @param {string} label
 * @param {string[]} tokens
 */
function highlight(title, label, tokens) {
  const folded = fold(label);
  /** @type {boolean[]} */
  const marked = new Array(label.length).fill(false);
  if (folded.length === label.length) {
    for (const token of tokens) {
      const at = folded.indexOf(token);
      if (at >= 0) marked.fill(true, at, at + token.length);
    }
  }
  title.replaceChildren();
  let start = 0;
  for (let at = 1; at <= label.length; at++) {
    if (at < label.length && marked[at] === marked[start]) continue;
    const part = label.slice(start, at);
    if (marked[start]) {
      const mark = document.createElement('mark');
      mark.textContent = part;
      title.append(mark);
    } else {
      title.append(part);
    }
    start = at;
  }
}

/**
 * `option` as it is matched, `order`th in the page.
 * @param {HTMLAnchorElement} option
 * @param {number} order
 * @returns {Entry}
 */
function entry(option, order) {
  const label = option.querySelector('.result-title')?.textContent ?? '';
  const trail = option.querySelector('small')?.textContent ?? '';
  const other = fold(`${trail} ${option.dataset.terms ?? ''}`);
  const title = fold(label);
  return {
    option,
    title,
    titleWords: words(title),
    other,
    otherWords: words(other),
    label,
    order
  };
}

/**
 * The options of `root`.
 * @param {ParentNode} root
 */
const optionsOf = (root) =>
  /** @type {HTMLAnchorElement[]} */ ([...root.querySelectorAll('a[role="option"]')]);

/**
 * Wires the top bar's search `form`, as above.
 * @param {HTMLFormElement} form
 */
function wireSearch(form) {
  const input = form.querySelector('input[role="combobox"]');
  const panel = form.querySelector('.results');
  const list = panel?.querySelector('[role="listbox"]');
  const empty = panel?.querySelector('.results-empty');
  const source = form.querySelector('template.search-source');
  if (
    !(input instanceof HTMLInputElement) ||
    !(panel instanceof HTMLElement) ||
    !(list instanceof HTMLElement) ||
    !(empty instanceof HTMLElement) ||
    !(source instanceof HTMLTemplateElement)
  )
    return;
  // The results, held outside the document but for the groups the list shows.
  const held = /** @type {DocumentFragment} */ (source.content.cloneNode(true));
  form.hidden = false;
  const all = held.querySelector('[data-all]');
  const allGroup = all?.closest('[data-group]') ?? null;
  const allQuery = all?.querySelector('q');
  const suggest = form.dataset.suggest;
  /** The groups the page holds, and their results. */
  const groups = /** @type {HTMLElement[]} */ ([...held.querySelectorAll('[data-group]')]).filter(
    (group) => group !== allGroup
  );
  const entries = groups
    .flatMap((group) => optionsOf(group))
    .map((option, order) => entry(option, order));
  for (const [index, option] of optionsOf(held).entries())
    option.id = `search-result-${String(index)}`;
  /**
   * The groups the server answered for `answered`, which the list shows.
   * @type {{ query: string; groups: HTMLElement[] }}
   */
  let remote = { query: '', groups: [] };
  /** @type {Map<string, string>} */
  const answers = new Map();
  /** @type {AbortController | undefined} */
  let asking;
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let pause;
  /** @type {HTMLAnchorElement | undefined} */
  let active;

  /** The query as the server is asked it, and its answers are kept by. */
  const asked = () => input.value.trim().toLowerCase();

  /** The results shown, in order. */
  const shown = () => optionsOf(list).filter((option) => !option.closest('[hidden]'));

  /**
   * Makes `option` the result Enter follows, if any.
   * @param {HTMLAnchorElement | undefined} option
   */
  const choose = (option) => {
    active?.removeAttribute('aria-selected');
    active = option;
    if (option) {
      option.setAttribute('aria-selected', 'true');
      input.setAttribute('aria-activedescendant', option.id);
      option.scrollIntoView({ block: 'nearest' });
    } else {
      input.removeAttribute('aria-activedescendant');
    }
  };

  /**
   * Opens the list, ranked for the query, or closes it, emptied.
   * @param {boolean} open
   */
  const toggle = (open) => {
    panel.hidden = !open;
    input.setAttribute('aria-expanded', String(open));
    if (open) {
      render();
    } else {
      choose(undefined);
      list.replaceChildren();
    }
  };

  /** Ranks every result for the query, and lists the best of each group. */
  const render = () => {
    if (panel.hidden) return;
    const query = fold(input.value.trim());
    const tokens = words(query);
    /** @type {Map<HTMLElement, number>} The best score of each group shown. */
    const best = new Map();
    for (const group of groups) {
      const ranked = entries
        .filter((one) => group.contains(one.option))
        .map((one) => ({
          one,
          score: tokens.length ? score(one, tokens) : group.dataset.group === 'pages' ? 1 : 0
        }))
        .filter(({ score }) => score > 0)
        .sort(
          (a, b) =>
            b.score - a.score ||
            a.one.title.length - b.one.title.length ||
            a.one.order - b.one.order
        );
      const kept = new Set(
        ranked.slice(0, tokens.length ? SHOWN : undefined).map(({ one }) => one)
      );
      for (const one of entries.filter((one) => group.contains(one.option))) {
        one.option.hidden = !kept.has(one);
        const title = one.option.querySelector('.result-title');
        if (title instanceof HTMLElement) highlight(title, one.label, tokens);
      }
      // Ranked first, then the rest as they were.
      group.append(...ranked.map(({ one }) => one.option));
      if (kept.size) best.set(group, ranked[0]?.score ?? 0);
    }
    // The server's groups rank between a word's start and anything weaker.
    const current = remote.query === asked() ? remote.groups : [];
    for (const group of current) {
      for (const option of optionsOf(group)) {
        const title = option.querySelector('.result-title');
        if (title instanceof HTMLElement) highlight(title, title.textContent, tokens);
      }
      best.set(group, 60 * tokens.length);
    }
    const order = [...best].sort(([, a], [, b]) => b - a).map(([group]) => group);
    if (query && all instanceof HTMLAnchorElement && allGroup instanceof HTMLElement && allQuery) {
      const url = new URL(form.action);
      url.searchParams.set('q', input.value.trim());
      all.href = url.href;
      allQuery.textContent = input.value.trim();
      order.push(allGroup);
    }
    list.replaceChildren(...order);
    const results = shown();
    const waiting = !!suggest && asked().length >= ASKED && remote.query !== asked();
    empty.hidden = results.some((option) => !option.hasAttribute('data-all')) || waiting;
    choose(results[0]);
  };

  /**
   * Shows `html`, the server's groups for `query`, if it is still the query.
   * @param {string} query
   * @param {string} html
   */
  const answered = (query, html) => {
    if (asked() !== query) return;
    const parsed = new DOMParser().parseFromString(html, 'text/html');
    const groups = /** @type {HTMLElement[]} */ ([...parsed.body.querySelectorAll('[data-group]')]);
    let index = 0;
    for (const group of groups) {
      for (const option of optionsOf(group)) option.id = `search-found-${String(index++)}`;
    }
    remote = { query, groups: groups.map((group) => document.adoptNode(group)) };
    render();
  };

  /**
   * Asks the server what else the query finds, unless it knows already: from
   * its answer to this query, or to a shorter one this query contains which
   * found nothing, as the server finds what contains the query.
   */
  const ask = () => {
    clearTimeout(pause);
    asking?.abort();
    const query = asked();
    if (!suggest || query.length < ASKED) return;
    const known =
      answers.get(query) ??
      (!ID.test(query) && [...answers].some(([shorter, html]) => !html && query.includes(shorter))
        ? ''
        : undefined);
    if (known !== undefined) {
      answered(query, known);
      return;
    }
    pause = setTimeout(() => {
      const controller = new AbortController();
      asking = controller;
      const url = new URL(suggest, window.location.href);
      url.searchParams.set('q', input.value.trim());
      form.setAttribute('aria-busy', 'true');
      fetch(url, { signal: controller.signal, headers: { accept: 'text/html' } })
        .then(async (response) => {
          if (!response.ok) throw new Error(`search answered ${String(response.status)}`);
          const html = await response.text();
          if (answers.size > 50) answers.clear();
          answers.set(query, html);
          answered(query, html);
        })
        // A failed request finds nothing more than the page's own results; an
        // aborted one gave way to a newer query.
        .catch(() => {
          if (!controller.signal.aborted) answered(query, '');
        })
        .finally(() => {
          if (asking === controller) form.removeAttribute('aria-busy');
        });
    }, PAUSE);
  };

  input.addEventListener('input', () => {
    toggle(true);
    ask();
  });
  input.addEventListener('focus', () => {
    toggle(true);
  });
  form.addEventListener('focusout', (event) => {
    if (!(event.relatedTarget instanceof Node) || !form.contains(event.relatedTarget))
      toggle(false);
  });
  // Keeps the focus in the input, so a click on a result is not lost to closing.
  list.addEventListener('pointerdown', (event) => {
    event.preventDefault();
  });
  list.addEventListener('pointermove', (event) => {
    const option =
      event.target instanceof Element ? event.target.closest('a[role="option"]') : null;
    if (option instanceof HTMLAnchorElement && option !== active) choose(option);
  });
  input.addEventListener('keydown', (event) => {
    switch (event.key) {
      case 'ArrowDown':
      case 'ArrowUp': {
        event.preventDefault();
        if (panel.hidden) toggle(true);
        const results = shown();
        const at = active ? results.indexOf(active) : -1;
        const step = event.key === 'ArrowDown' ? 1 : -1;
        choose(results[(at + step + results.length) % results.length]);
        break;
      }
      case 'Enter':
        if (event.isComposing) break;
        if (active && !panel.hidden) {
          event.preventDefault();
          active.click();
        } else if (!form.getAttribute('action')) {
          event.preventDefault();
        }
        break;
      case 'Escape':
        if (!panel.hidden) {
          event.preventDefault();
          toggle(false);
        } else if (input.value) {
          input.value = '';
        } else {
          input.blur();
        }
        break;
    }
  });
  document.addEventListener('keydown', (event) => {
    const target = event.target;
    const typing =
      target instanceof HTMLElement &&
      (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName));
    const slash = event.key === '/' && !typing;
    const k = event.key.toLowerCase() === 'k' && (event.ctrlKey || event.metaKey);
    if (!slash && !k) return;
    event.preventDefault();
    input.focus();
    input.select();
  });
  // A page restored from the back/forward cache closes what it left open.
  window.addEventListener('pageshow', () => {
    toggle(false);
  });
}

/**
 * Wires the live search `input`, as above.
 * @param {HTMLInputElement} input
 */
function wireLive(input) {
  const form = input.form;
  const regions = (input.dataset.live ?? '').split(' ').filter(Boolean);
  if (!form || !regions.length) return;
  /** @type {AbortController | undefined} */
  let asking;
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let pause;
  const refresh = () => {
    asking?.abort();
    const submitter = form.querySelector('[data-live-submit]');
    // The form is checked as its submitter would have it, before it is sent.
    const unchecked = form.noValidate || !!submitter?.hasAttribute('formnovalidate');
    if (!unchecked && !form.checkValidity()) return;
    const controller = new AbortController();
    asking = controller;
    const data = new FormData(form, submitter instanceof HTMLButtonElement ? submitter : null);
    const fields = new URLSearchParams();
    for (const [name, value] of data) if (typeof value === 'string') fields.append(name, value);
    const get = form.method === 'get';
    const url = new URL(form.action);
    if (get) url.search = fields.toString();
    form.setAttribute('aria-busy', 'true');
    fetch(url, {
      method: form.method,
      body: get ? null : fields,
      signal: controller.signal,
      headers: { accept: 'text/html' }
    })
      .then(async (response) => {
        if (!response.ok) return;
        const page = new DOMParser().parseFromString(await response.text(), 'text/html');
        for (const id of regions) {
          const fresh = page.getElementById(id);
          const old = document.getElementById(id);
          if (fresh && old) old.replaceWith(document.adoptNode(fresh));
        }
        if (get) window.history.replaceState(window.history.state, '', url);
      })
      // An aborted or failed refresh leaves the results shown.
      .catch(() => undefined)
      .finally(() => {
        if (asking === controller) form.removeAttribute('aria-busy');
      });
  };
  input.addEventListener('input', () => {
    clearTimeout(pause);
    pause = setTimeout(refresh, LIVE_PAUSE);
  });
}

/**
 * Opens the disclosure the address names, if it is one.
 */
function openTarget() {
  const id = decodeURIComponent(window.location.hash.slice(1));
  const target = id ? document.getElementById(id) : null;
  if (target instanceof HTMLDetailsElement) target.open = true;
}

for (const form of document.querySelectorAll('form[data-search]')) {
  if (form instanceof HTMLFormElement) wireSearch(form);
}
for (const input of document.querySelectorAll('input[data-live]')) {
  if (input instanceof HTMLInputElement) wireLive(input);
}
openTarget();
window.addEventListener('hashchange', openTarget);
