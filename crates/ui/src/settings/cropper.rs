//! Choosing which square of a new picture auth keeps: the chosen image moves and
//! zooms under a circle, as apps show it, and the square under the circle, in the
//! image's pixels, fills the form's [`CROP_X`], [`CROP_Y`] and [`CROP_SIZE`]
//! inputs. Without scripts they stay empty, and auth keeps the centred square.

use super::profile::{CROP_SIZE, CROP_X, CROP_Y, PICTURE_FIELD, PICTURE_TYPES};
use crate::browser::{AsyncHandler, Browser};
use topcoat::{
    Result,
    context::Cx,
    runtime::{Event, Expr, Signal, expr, signal},
    view::{View, component, element_id, view},
};

/// How far one arrow key moves the image, in screen pixels.
const STEP: f64 = 8.0;

/// The cropper's state in the browser: the image, the stage showing it, and the
/// square kept, held as its centre in the image's pixels. Moving or zooming
/// keeps the square inside the image.
struct Cropper {
    /// The file input's ID.
    file: String,
    /// The image's ID.
    image: String,
    /// The stage's ID.
    stage: String,
    /// The URL of the file shown, revoked once replaced; empty without one.
    url: Signal<String>,
    /// The image's width, in its pixels; zero while none shows.
    width: Signal<f64>,
    /// The image's height, in its pixels.
    height: Signal<f64>,
    /// The square's centre, as last moved, in the image's pixels.
    x: Signal<f64>,
    /// See `x`.
    y: Signal<f64>,
    /// How far it zooms in: one covers the stage with the image.
    zoom: Signal<f64>,
    /// The stage's side, in screen pixels: none while its dialog is closed.
    side: Signal<f64>,
    /// The pointer dragging the image, and where it was: `-1` without one.
    drag: Signal<f64>,
    /// See `drag`.
    drag_x: Signal<f64>,
    /// See `drag`.
    drag_y: Signal<f64>,
}

impl Cropper {
    /// A cropper showing no image yet.
    fn new(cx: &Cx) -> Self {
        Self {
            file: element_id(cx),
            image: element_id(cx),
            stage: element_id(cx),
            url: signal(cx, String::new),
            width: signal(cx, || 0.0),
            height: signal(cx, || 0.0),
            x: signal(cx, || 0.0),
            y: signal(cx, || 0.0),
            zoom: signal(cx, || 1.0),
            side: signal(cx, || 0.0),
            drag: signal(cx, || -1.0),
            drag_x: signal(cx, || 0.0),
            drag_y: signal(cx, || 0.0),
        }
    }

    /// Screen pixels per image pixel: the image covers the stage, times the zoom.
    fn scale(&self) -> Expr<f64> {
        let (width, height, zoom, side) = (
            self.width.clone(),
            self.height.clone(),
            self.zoom.clone(),
            self.side.clone(),
        );
        expr!({
            let short = if width.get() < height.get() {
                width.get()
            } else {
                height.get()
            };
            side.get() / short * zoom.get()
        })
    }

    /// The square's centre on `axis`, `centre` as last moved, kept so the square
    /// stays inside the image's `length` on that axis.
    fn centre(&self, centre: &Signal<f64>, length: &Signal<f64>) -> Expr<f64> {
        let (centre, length, side, scale) = (
            centre.clone(),
            length.clone(),
            self.side.clone(),
            self.scale(),
        );
        expr!({
            let half = side.get() / scale / 2.0;
            let high = length.get() - half;
            let below = if centre.get() < high {
                centre.get()
            } else {
                high
            };
            if below > half { below } else { half }
        })
    }

    /// The square's side, in the image's pixels: at least one.
    fn size(&self) -> Expr<f64> {
        let (side, scale) = (self.side.clone(), self.scale());
        let rounded = Browser::round(&expr!(side.get() / scale));
        expr!(if rounded > 1.0 { rounded } else { 1.0 })
    }

    /// What the form's input sends of `value`: nothing while no image shows, or
    /// the stage has no size yet.
    fn sent(&self, value: &Expr<f64>) -> Expr<String> {
        let (width, side, text) = (self.width.clone(), self.side.clone(), Browser::text(value));
        expr!(if width.get() == 0.0 {
            "".to_owned()
        } else if side.get() == 0.0 {
            "".to_owned()
        } else {
            text
        })
    }

    /// The square's edge on the axis of `centre` and the image's `length`, kept
    /// inside the image, as the form's input sends it.
    fn edge(&self, centre: &Signal<f64>, length: &Signal<f64>) -> Expr<String> {
        let (centre, length, side) = (self.centre(centre, length), length.clone(), self.size());
        let edge = Browser::round(&expr!(centre - side / 2.0));
        self.sent(&expr!({
            let high = length.get() - side;
            let below = if edge < high { edge } else { high };
            if below > 0.0 { below } else { 0.0 }
        }))
    }

    /// Places the image so the square shows under the circle.
    fn place(&self) -> Expr<()> {
        let (width, side, scale) = (self.width.clone(), self.side.clone(), self.scale());
        let (x, y) = (
            self.centre(&self.x, &self.width),
            self.centre(&self.y, &self.height),
        );
        let image = self.image.clone();
        expr!({
            let _width = width.get() * scale;
            let _left = side.get() / 2.0 - x * scale;
            let _top = side.get() / 2.0 - y * scale;
            // The policy allows no inline style, but sets it through the CSSOM.
            raw!(
                "((image) => { image.style.width = String(${_width}) + 'px'; image.style.transform = 'translate(' + String(${_left}) + 'px, ' + String(${_top}) + 'px)'; })(document.getElementById(String(${image})))",
                ()
            )
        })
    }

    /// The file input's `@change` handler, which shows the file chosen, or
    /// nothing once none is. The last image's square must not go with the next.
    fn choose(&self) -> Expr<impl FnOnce(Event) + use<>> {
        let (url, width, file) = (self.url.clone(), self.width.clone(), self.file.clone());
        expr!(|_e: Event| {
            width.set(0.0);
            let _shown = url.get();
            url.set(raw!(
                "cx.hydrate(((input, shown) => { if (shown) URL.revokeObjectURL(shown); const file = input.files?.[0]; return file ? URL.createObjectURL(file) : ''; })(document.getElementById(String(${file})), String(${_shown})))",
                String::new()
            ));
        })
    }

    /// The image's `@load` handler, which starts on its centred square, at no
    /// zoom, once the cropper shows and its stage has a size.
    fn loaded(&self) -> Expr<impl AsyncHandler + use<>> {
        let (width, height, zoom) = (self.width.clone(), self.height.clone(), self.zoom.clone());
        let (x, y, side, place) = (
            self.x.clone(),
            self.y.clone(),
            self.side.clone(),
            self.place(),
        );
        let (image, stage) = (self.image.clone(), self.stage.clone());
        expr!(async |_e: Event| {
            width.set(raw!(
                "cx.hydrate(document.getElementById(String(${image})).naturalWidth)",
                0.0
            ));
            height.set(raw!(
                "cx.hydrate(document.getElementById(String(${image})).naturalHeight)",
                0.0
            ));
            x.set(width.get() / 2.0);
            y.set(height.get() / 2.0);
            zoom.set(1.0);
            // The cropper shows once the page applies the width.
            let _shown = raw!("await Promise.resolve()", ());
            side.set(raw!(
                "cx.hydrate(document.getElementById(String(${stage})).clientWidth)",
                0.0
            ));
            let _placed = place;
        })
    }

    /// The stage's `@mount` handler, which follows its side: it changes with the
    /// window, and is none while its dialog is closed.
    fn observe(&self) -> Expr<impl FnOnce(Event) + use<>> {
        let (side, stage, place) = (self.side.clone(), self.stage.clone(), self.place());
        expr!(|_e: Event| {
            raw!(
                "new ResizeObserver(() => { ${side}.set(cx.hydrate(document.getElementById(String(${stage})).clientWidth)); ${place}; }).observe(document.getElementById(String(${stage})))",
                ()
            )
        })
    }

    /// The stage's `@pointerdown` handler, which starts dragging with the main
    /// button.
    fn grab(&self) -> Expr<impl FnOnce(Event) + use<>> {
        let (drag, drag_x, drag_y) = (self.drag.clone(), self.drag_x.clone(), self.drag_y.clone());
        let stage = self.stage.clone();
        expr!(|e: Event| {
            if e.button == 0.0 {
                drag.set(e.pointer_id);
                drag_x.set(e.client_x);
                drag_y.set(e.client_y);
                let _pointer = drag.get();
                let _captured = raw!(
                    "document.getElementById(String(${stage})).setPointerCapture(${_pointer}.dehydrate())",
                    ()
                );
            }
        })
    }

    /// The stage's `@pointermove` handler, which moves the image with the pointer
    /// dragging it, and no other; the square moves the other way.
    fn drag(&self) -> Expr<impl FnOnce(Event) + use<>> {
        let (drag, drag_x, drag_y) = (self.drag.clone(), self.drag_x.clone(), self.drag_y.clone());
        let (x, y, scale, place) = (self.x.clone(), self.y.clone(), self.scale(), self.place());
        let (from_x, from_y) = (
            self.centre(&self.x, &self.width),
            self.centre(&self.y, &self.height),
        );
        expr!(|e: Event| {
            if drag.get() == e.pointer_id {
                let last_x = drag_x.get();
                let last_y = drag_y.get();
                drag_x.set(e.client_x);
                drag_y.set(e.client_y);
                x.set(from_x - (drag_x.get() - last_x) / scale);
                y.set(from_y - (drag_y.get() - last_y) / scale);
                let _placed = place;
            }
        })
    }

    /// The stage's `@pointerup` and `@pointercancel` handler, which ends dragging
    /// with that pointer.
    fn release(&self) -> Expr<impl FnOnce(Event) + use<>> {
        let drag = self.drag.clone();
        expr!(|e: Event| {
            if drag.get() == e.pointer_id {
                drag.set(-1.0);
            }
        })
    }

    /// The stage's `@keydown` handler, which moves the image with the arrow keys.
    fn key(&self) -> Expr<impl FnOnce(Event) + use<>> {
        let (x, y, scale, place) = (self.x.clone(), self.y.clone(), self.scale(), self.place());
        let (from_x, from_y) = (
            self.centre(&self.x, &self.width),
            self.centre(&self.y, &self.height),
        );
        expr!(|e: Event| {
            let dx = if e.key == "ArrowLeft" {
                -STEP
            } else if e.key == "ArrowRight" {
                STEP
            } else {
                0.0
            };
            let dy = if e.key == "ArrowUp" {
                -STEP
            } else if e.key == "ArrowDown" {
                STEP
            } else {
                0.0
            };
            if dx != 0.0 {
                e.prevent_default();
                x.set(from_x - dx / scale);
                let _placed = place;
            } else if dy != 0.0 {
                e.prevent_default();
                y.set(from_y - dy / scale);
                let _placed = place;
            }
        })
    }

    /// The zoom input's `@input` handler.
    fn zoomed(&self) -> Expr<impl FnOnce(Event) + use<>> {
        let (zoom, place) = (self.zoom.clone(), self.place());
        expr!(|e: Event| {
            let _value = e.target.value;
            zoom.set(raw!("cx.hydrate(Number(String(${_value})))", 1.0));
            let _placed = place;
        })
    }
}

/// The picture input of the profile's picture form, and the cropper choosing which
/// square of the image chosen auth keeps.
#[component]
pub(super) async fn picture_input(cx: &Cx) -> Result<impl View> {
    let crop = Cropper::new(cx);
    let (url, width, zoom) = (crop.url.clone(), crop.width.clone(), crop.zoom.clone());
    Ok(view! {
        <label>
            "Picture"
            <input
                type="file"
                id=(crop.file.as_str())
                name=(PICTURE_FIELD)
                accept=(PICTURE_TYPES)
                required=""
                autofocus=""
                @change=(crop.choose())
            >
        </label>
        <div class="cropper" :hidden=$(width.get() == 0.0)>
            <div
                class="crop-stage"
                id=(crop.stage.as_str())
                tabindex="0"
                role="application"
                aria-label="The part of the picture apps show. Drag it, or use the arrow keys, to move it."
                @mount=(crop.observe())
                @pointerdown=(crop.grab())
                @pointermove=(crop.drag())
                @pointerup=(crop.release())
                @pointercancel=(crop.release())
                @keydown=(crop.key())
            >
                <img
                    alt=""
                    id=(crop.image.as_str())
                    :src=$(url.get())
                    @load=(crop.loaded())
                    @error=$(|_e: Event| width.set(0.0))
                >
            </div>
            <label>
                "Zoom"
                <input
                    type="range"
                    min="1"
                    max="4"
                    step="0.01"
                    :value=$(zoom.get())
                    @input=(crop.zoomed())
                >
            </label>
        </div>
        <input type="hidden" name=(CROP_X) :value=(crop.edge(&crop.x, &crop.width))>
        <input type="hidden" name=(CROP_Y) :value=(crop.edge(&crop.y, &crop.height))>
        <input type="hidden" name=(CROP_SIZE) :value=(crop.sent(&crop.size()))>
    })
}
