/*
 * cinematic-endcard.js
 *
 * Shared brand endcard for the cipher cinematic library. Exposes one
 * function on the window:
 *
 *   window.cipherPaintBrandEndCard(stage)
 *
 * Every cinematic calls this when its final scene completes. The
 * endcard paints the cipher mark and wordmark on a deep-black curtain.
 *
 * The mark is a thin circle, traversed clockwise by a single dot:
 * one full cycle, then the dot rests at 12 o'clock and a hairline
 * bisects the disc. The wordmark and tagline settle below. The
 * metaphor is the encryption cycle, completing.
 *
 * Pure monochrome. No accent color.
 */

(function () {
  var SVG_NS = 'http://www.w3.org/2000/svg';
  var REDUCED =
    window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function el(tag, attrs, parent) {
    var node = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      for (var k in attrs) {
        if (Object.prototype.hasOwnProperty.call(attrs, k)) {
          node.setAttribute(k, attrs[k]);
        }
      }
    }
    if (parent) parent.appendChild(node);
    return node;
  }

  function animate(durMs, onTick, onDone) {
    if (REDUCED) {
      if (onTick) onTick(1);
      if (onDone) onDone();
      return;
    }
    var start = null;
    function frame(ts) {
      if (start === null) start = ts;
      var t = Math.min(1, (ts - start) / durMs);
      onTick(t);
      if (t < 1) requestAnimationFrame(frame);
      else if (onDone) onDone();
    }
    requestAnimationFrame(frame);
  }

  function easeOut(t) {
    return 1 - Math.pow(1 - t, 3);
  }

  function easeInOut(t) {
    return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
  }

  function defer(fn, ms) {
    if (REDUCED) { try { fn(); } catch (e) {} return; }
    setTimeout(function () { try { fn(); } catch (e) {} }, ms);
  }

  window.cipherPaintBrandEndCard = function (stage) {
    if (!stage) return;
    while (stage.firstChild) stage.removeChild(stage.firstChild);

    var cx = 550, cy = 270, R = 80;
    var CIRC = 2 * Math.PI * R;

    // Curtain: a deep black wash over whatever was on the stage.
    var curtain = el('rect', {
      x: 0, y: 0, width: 1100, height: 619,
      fill: '#0a0a0a', opacity: 0
    }, stage);
    animate(600, function (t) {
      curtain.setAttribute('opacity', 0.97 * easeOut(t));
    });

    // Thin outer circle, drawn via stroke-dashoffset.
    var ring = el('circle', {
      cx: cx, cy: cy, r: R,
      fill: 'none',
      stroke: '#f5f5f5',
      'stroke-width': 1.5,
      'stroke-dasharray': CIRC,
      'stroke-dashoffset': CIRC,
      opacity: 0
    }, stage);
    defer(function () {
      animate(900, function (t) {
        var e = easeInOut(t);
        ring.setAttribute('opacity', 0.9 * e);
        ring.setAttribute('stroke-dashoffset', CIRC * (1 - e));
      });
    }, 300);

    // Inner soft ring, just decorative.
    defer(function () {
      var inner = el('circle', {
        cx: cx, cy: cy, r: R - 26,
        fill: 'none',
        stroke: 'rgba(245,245,245,0.18)',
        'stroke-width': 1,
        opacity: 0
      }, stage);
      animate(500, function (t) {
        inner.setAttribute('opacity', easeOut(t));
      });
    }, 800);

    // Dot at 12 o'clock, traversing the ring once clockwise.
    defer(function () {
      var dot = el('circle', {
        cx: cx,
        cy: cy - R,
        r: 4.5,
        fill: '#ffffff',
        opacity: 0
      }, stage);
      // Fade in
      animate(250, function (t) { dot.setAttribute('opacity', easeOut(t)); });
      // Glow
      var glow = el('circle', {
        cx: cx, cy: cy - R,
        r: 4.5, fill: 'none',
        stroke: 'rgba(255,255,255,0.4)',
        'stroke-width': 1,
        opacity: 0
      }, stage);
      animate(250, function (t) { glow.setAttribute('opacity', easeOut(t)); });

      // Trail: leave a faint arc behind the dot to show the path
      // traversed. Painted as a partial circle whose stroke-dashoffset
      // shrinks as the dot moves.
      var trail = el('circle', {
        cx: cx, cy: cy, r: R,
        fill: 'none',
        stroke: 'rgba(255,255,255,0.35)',
        'stroke-width': 1.5,
        'stroke-dasharray': CIRC,
        'stroke-dashoffset': CIRC,
        transform: 'rotate(-90 ' + cx + ' ' + cy + ')'
      }, stage);

      // Full traversal, clockwise from 12 o'clock.
      defer(function () {
        animate(1700, function (t) {
          var e = easeInOut(t);
          var angle = -Math.PI / 2 + (2 * Math.PI) * e;
          var x = cx + R * Math.cos(angle);
          var y = cy + R * Math.sin(angle);
          dot.setAttribute('cx', x);
          dot.setAttribute('cy', y);
          glow.setAttribute('cx', x);
          glow.setAttribute('cy', y);
          glow.setAttribute('r', 4.5 + 6 * (1 - e) + 3 * e);
          glow.setAttribute('opacity', 0.4 + 0.2 * Math.sin(e * Math.PI * 4));
          trail.setAttribute('stroke-dashoffset', CIRC * (1 - e));
        }, function () {
          // Settle.
          dot.setAttribute('cx', cx);
          dot.setAttribute('cy', cy - R);
          glow.setAttribute('cx', cx);
          glow.setAttribute('cy', cy - R);
          glow.setAttribute('r', 7.5);
          glow.setAttribute('opacity', 0.6);
        });
      }, 300);
    }, 1400);

    // Horizontal hairline that bisects the disc as the dot lands.
    defer(function () {
      var line = el('line', {
        x1: cx, y1: cy, x2: cx, y2: cy,
        stroke: '#f5f5f5',
        'stroke-width': 1,
        opacity: 0.5
      }, stage);
      animate(600, function (t) {
        var e = easeOut(t);
        var halfW = (R + 26) * e;
        line.setAttribute('x1', cx - halfW);
        line.setAttribute('x2', cx + halfW);
      });
    }, 3500);

    // Wordmark.
    defer(function () {
      var word = el('text', {
        x: cx, y: cy + 130,
        fill: '#f5f5f5',
        'font-family':
          '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        'font-size': 56,
        'font-weight': 700,
        'letter-spacing': 1,
        'text-anchor': 'middle',
        opacity: 0
      }, stage);
      word.textContent = 'cipher';
      animate(700, function (t) {
        word.setAttribute('opacity', easeOut(t));
      });
    }, 3800);

    // Hairline under the wordmark.
    defer(function () {
      var u = el('line', {
        x1: cx, y1: cy + 152, x2: cx, y2: cy + 152,
        stroke: '#f5f5f5',
        'stroke-width': 1,
        opacity: 0.5
      }, stage);
      animate(500, function (t) {
        var e = easeOut(t);
        u.setAttribute('x1', cx - 50 * e);
        u.setAttribute('x2', cx + 50 * e);
      });
    }, 4200);

    // Tagline.
    defer(function () {
      var tag = el('text', {
        x: cx, y: cy + 188,
        fill: '#9a9a9a',
        'font-family':
          '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        'font-size': 12,
        'font-weight': 400,
        'letter-spacing': 7,
        'text-anchor': 'middle',
        opacity: 0
      }, stage);
      tag.textContent = 'PROGRAMMATIC . SOPS . FROM GO';
      animate(700, function (t) {
        tag.setAttribute('opacity', 0.85 * easeOut(t));
      });
    }, 4500);
  };
})();
