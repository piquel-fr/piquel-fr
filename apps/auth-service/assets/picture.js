/**
 * The picture script: it lets the profile's picture form choose which square of the
 * chosen image auth keeps. The image moves and zooms under a circle, as apps show
 * it, and the square under the circle, in the image's pixels, fills the form's
 * hidden inputs. Without the script they stay empty and auth keeps the centred
 * square. It exports nothing, and nothing compiles it: auth embeds this file as it
 * is, under a path naming its content, and `tsc` only checks its JSDoc types.
 */

/** How far one arrow key moves the image, in screen pixels. */
const STEP = 8;

/**
 * The cropper of one form: its image, its zoom, and the square it keeps, held as
 * the square's centre in the image's pixels.
 */
class Cropper {
  /** @param {HTMLFormElement} form */
  constructor(form) {
    this.file = query(form, 'input[type="file"]', HTMLInputElement);
    this.cropper = query(form, '[data-cropper]', HTMLElement);
    this.stage = query(form, '[data-crop-stage]', HTMLElement);
    this.image = query(form, '[data-crop-image]', HTMLImageElement);
    this.zoom = query(form, '[data-crop-zoom]', HTMLInputElement);
    /** The hidden inputs of the square's left edge, top edge and side. */
    this.fields = ['x', 'y', 'size'].map((part) =>
      query(form, `[data-crop="${part}"]`, HTMLInputElement)
    );
    /** The image's size and the square's centre, in its pixels. */
    this.width = 0;
    this.height = 0;
    this.centreX = 0;
    this.centreY = 0;
    /** @type {{ id: number; x: number; y: number } | null} The pointer dragging the image. */
    this.drag = null;
    /** @type {string | null} The URL of the file shown, revoked once replaced. */
    this.url = null;

    this.file.addEventListener('change', () => {
      this.choose();
    });
    this.image.addEventListener('load', () => {
      this.loaded();
    });
    this.image.addEventListener('error', () => {
      this.reset();
    });
    this.zoom.addEventListener('input', () => {
      this.render();
    });
    this.stage.addEventListener('pointerdown', (event) => {
      this.grab(event);
    });
    this.stage.addEventListener('pointermove', (event) => {
      this.move(event);
    });
    for (const end of /** @type {const} */ (['pointerup', 'pointercancel'])) {
      this.stage.addEventListener(end, (event) => {
        if (event.pointerId === this.drag?.id) this.drag = null;
      });
    }
    this.stage.addEventListener('keydown', (event) => {
      this.key(event);
    });
    // The stage changes size with the window, and has none while its dialog is
    // closed.
    new ResizeObserver(() => {
      this.render();
    }).observe(this.stage);
  }

  /** Shows the file just chosen, or nothing once none is. */
  choose() {
    // The last image's square must not go with the next one.
    this.reset();
    if (this.url) URL.revokeObjectURL(this.url);
    this.url = null;
    const file = this.file.files?.[0];
    if (!file) return;
    this.url = URL.createObjectURL(file);
    this.image.src = this.url;
  }

  /** Starts on the image's centred square, at no zoom. */
  loaded() {
    this.width = this.image.naturalWidth;
    this.height = this.image.naturalHeight;
    this.centreX = this.width / 2;
    this.centreY = this.height / 2;
    this.zoom.value = '1';
    this.cropper.hidden = false;
    this.render();
  }

  /** Hides the cropper and leaves the square to auth, until an image shows. */
  reset() {
    this.width = 0;
    this.cropper.hidden = true;
    for (const field of this.fields) field.value = '';
  }

  /** The stage's side, in screen pixels. */
  side() {
    return this.stage.clientWidth;
  }

  /** Screen pixels per image pixel: the image covers the stage, times the zoom. */
  scale() {
    return (this.side() / Math.min(this.width, this.height)) * Number(this.zoom.value);
  }

  /** Places the image so the square stays inside it, and writes the square. */
  render() {
    const side = this.side();
    if (!this.width || !side) return;
    const scale = this.scale();
    const half = side / scale / 2;
    this.centreX = clamp(this.centreX, half, this.width - half);
    this.centreY = clamp(this.centreY, half, this.height - half);
    const left = side / 2 - this.centreX * scale;
    const top = side / 2 - this.centreY * scale;
    this.image.style.width = `${String(this.width * scale)}px`;
    this.image.style.transform = `translate(${String(left)}px, ${String(top)}px)`;
    const size = Math.max(1, Math.round(side / scale));
    const square = [
      clamp(Math.round(this.centreX - size / 2), 0, this.width - size),
      clamp(Math.round(this.centreY - size / 2), 0, this.height - size),
      size
    ];
    this.fields.forEach((field, index) => (field.value = String(square[index])));
  }

  /** Starts dragging with the primary pointer's main button. @param {PointerEvent} event */
  grab(event) {
    if (!event.isPrimary || event.button !== 0) return;
    this.stage.setPointerCapture(event.pointerId);
    this.drag = { id: event.pointerId, x: event.clientX, y: event.clientY };
  }

  /** Moves the image with the pointer dragging it, and no other. @param {PointerEvent} event */
  move(event) {
    const drag = this.drag;
    if (drag?.id !== event.pointerId) return;
    this.pan(event.clientX - drag.x, event.clientY - drag.y);
    this.drag = { id: event.pointerId, x: event.clientX, y: event.clientY };
  }

  /** Moves the image with the arrow keys. @param {KeyboardEvent} event */
  key(event) {
    /** @type {Partial<Record<string, [number, number]>>} */
    const moves = {
      ArrowLeft: [-STEP, 0],
      ArrowRight: [STEP, 0],
      ArrowUp: [0, -STEP],
      ArrowDown: [0, STEP]
    };
    const by = moves[event.key];
    if (!by) return;
    event.preventDefault();
    this.pan(...by);
  }

  /**
   * Moves the image by `dx` and `dy` screen pixels, so the square moves the other way.
   * @param {number} dx
   * @param {number} dy
   */
  pan(dx, dy) {
    const scale = this.scale();
    this.centreX -= dx / scale;
    this.centreY -= dy / scale;
    this.render();
  }
}

/**
 * The element of `form` that `selector` names, which the page always renders, as a
 * `kind`.
 * @template {Element} T
 * @param {HTMLFormElement} form
 * @param {string} selector
 * @param {{ new (): T }} kind
 * @returns {T}
 */
function query(form, selector, kind) {
  const element = form.querySelector(selector);
  if (!(element instanceof kind)) throw new Error(`The picture form has no ${selector}.`);
  return element;
}

/**
 * `value`, within `low` and `high`; `low` when the range is empty.
 * @param {number} value
 * @param {number} low
 * @param {number} high
 */
function clamp(value, low, high) {
  return Math.max(low, Math.min(value, high));
}

for (const stage of document.querySelectorAll('[data-crop-stage]')) {
  const form = stage.closest('form');
  if (form) new Cropper(form);
}
