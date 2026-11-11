/**
 * The client form script, which auth's pages and the admin dashboard both load. It
 * exports nothing, and nothing compiles it: auth embeds this file as it is, under a
 * path naming its content, and `tsc` only checks its JSDoc types. Every page works
 * without it.
 *
 * A new client's form asks for its kind with radio buttons named `kind`, each
 * listing in `data-defaults` the switches its kind starts with on: its default
 * scopes, and `allow_refresh`. Choosing another kind turns on its defaults and off
 * the others those lists name, as long as they are still the last kind's defaults,
 * so a choice the user made stays.
 */

for (const form of document.forms) {
  const kinds = /** @type {HTMLInputElement[]} */ ([
    ...form.querySelectorAll('input[name="kind"][data-defaults]')
  ]);
  /**
   * The switches `kind` starts with on.
   * @param {HTMLInputElement} kind
   */
  const defaults = (kind) => new Set((kind.dataset.defaults ?? '').split(' '));
  const switches = [...new Set(kinds.flatMap((kind) => [...defaults(kind)]))]
    .map((name) => form.elements.namedItem(name))
    .filter((input) => input instanceof HTMLInputElement);
  let chosen = kinds.find((kind) => kind.checked);
  for (const kind of kinds)
    kind.addEventListener('change', () => {
      const last = chosen && defaults(chosen);
      if (last && switches.every((input) => input.checked === last.has(input.name)))
        for (const input of switches) input.checked = defaults(kind).has(input.name);
      chosen = kind;
    });
}
