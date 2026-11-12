/**
 * The copy script, which auth's pages and the admin dashboard both load. It
 * exports nothing, and nothing compiles it: auth embeds this file as it is, under
 * a path naming its content, and `tsc` only checks its JSDoc types. Every page
 * works without it: the value stays there to select.
 *
 * A `data-copy` button copies the text of the element its value names, and says
 * whether it did, for a moment, in the `role="status"` element just before it.
 * Clicking that element copies it too when it is a one-line value, in a
 * `.code-line`, unless the click selected some of it, so selecting part of a
 * value, or of a longer block such as a code example, still works. The button
 * starts hidden, and shows once the browser can write to the clipboard.
 */

if ('clipboard' in navigator)
  for (const button of /** @type {NodeListOf<HTMLButtonElement>} */ (
    document.querySelectorAll('button[data-copy]')
  )) {
    const status = button.previousElementSibling;
    const target = document.getElementById(button.dataset.copy ?? '');
    /** @type {ReturnType<typeof setTimeout> | undefined} */
    let cleared;
    /**
     * Says `message` in the button's status for a moment.
     * @param {string} message
     */
    const say = (message) => {
      if (!status) return;
      status.textContent = message;
      clearTimeout(cleared);
      cleared = setTimeout(() => (status.textContent = ''), 2000);
    };
    const copy = () => {
      navigator.clipboard.writeText(target?.textContent ?? '').then(
        () => {
          say('Copied');
        },
        () => {
          say('Could not copy: select the text instead');
        }
      );
    };
    button.hidden = false;
    button.addEventListener('click', copy);
    if (target?.closest('.code-line'))
      target.addEventListener('click', () => {
        if (window.getSelection()?.isCollapsed ?? true) copy();
      });
  }
