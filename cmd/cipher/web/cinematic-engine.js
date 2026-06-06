/*
 * cinematic-engine.js
 *
 * Shared scene engine for the cipher cinematic library. Each
 * explainer-<slug>.html shell loads this file, then loads the
 * per-cinematic explainer-<slug>.js which calls
 * window.cipherCinematic.run({ scenes: [...] }).
 *
 * The engine handles:
 *   - DOM grabs (stage, caption, controls, progress bar)
 *   - the runtime loop (rAF, scene sequencing, progress fill)
 *   - controls (pause, restart, skip)
 *   - click-and-drag scrubbing on the progress bar
 *   - tooltip showing the scene at the cursor (not the playhead)
 *   - visibilitychange pause when the tab backgrounds
 *   - prefers-reduced-motion honored everywhere
 *   - the brand end card via window.cipherPaintBrandEndCard
 *
 * Each scene is a plain object:
 *
 *   {
 *     label:    "1 / 8 . the pain",
 *     duration: 8000,
 *     caption:  "Short headline.<br/><span class='sub'>Subline.</span>",
 *     paint:    function (stage) { ... return optionalTeardownFn; },
 *   }
 *
 * Scenes must be re-entrant. The engine calls paint() again every time
 * the user scrubs into the scene. State that survives across scenes
 * lives on the stage as appended SVG, which the engine clears between
 * scenes via clearStage().
 */

(function () {
  var SVG_NS = 'http://www.w3.org/2000/svg';
  var REDUCED =
    window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var COL = {
    accent: '#f96302',
    accentSoft: 'rgba(249,99,2,0.18)',
    success: '#5ac994',
    warning: '#f9b342',
    critical: '#f06262',
    vault: '#7ea9ff',
    registry: '#c98ef8',
    text: '#f0f6fc',
    body: '#c9d1d9',
    muted: '#8b949e',
    bgDark: '#06090f',
    bgLight: '#0d1320'
  };

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

  function text(parent, x, y, str, opts) {
    opts = opts || {};
    var t = el(
      'text',
      {
        x: x,
        y: y,
        fill: opts.fill || COL.body,
        'font-family':
          opts.family ||
          '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        'font-size': opts.size || 16,
        'font-weight': opts.weight || 400,
        'text-anchor': opts.anchor || 'start',
        'letter-spacing': opts.tracking || 0,
        opacity: opts.opacity != null ? opts.opacity : 1
      },
      parent
    );
    if (str != null) t.textContent = str;
    return t;
  }

  function easeInOut(t) {
    return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
  }

  function easeOut(t) {
    return 1 - Math.pow(1 - t, 3);
  }

  /*
   * Engine state.
   */
  var stage = null;
  var caption = null;
  var sceneLabel = null;
  var progressFill = null;
  var progressTrack = null;
  var progressHead = null;
  var progressTooltip = null;
  var pauseBtn = null;
  var replayBtn = null;
  var skipBtn = null;

  var SCENES = [];
  var idx = 0;
  var paused = false;
  var sceneStart = 0;
  var elapsedInPaused = 0;
  var pending = [];
  var currentTeardown = null;
  var rafId = 0;
  var dragging = false;

  function bind() {
    stage = document.getElementById('cipher-explainer-stage');
    caption = document.getElementById('cipher-explainer-caption');
    sceneLabel = document.getElementById('cipher-explainer-scene-label');
    progressFill = document.getElementById('cipher-explainer-progress-fill');
    progressTrack = document.getElementById('cipher-explainer-progress');
    progressHead = document.getElementById('cipher-explainer-progress-head');
    progressTooltip = document.getElementById('cipher-explainer-progress-tooltip');
    pauseBtn = document.getElementById('cipher-explainer-pause');
    replayBtn = document.getElementById('cipher-explainer-replay');
    skipBtn = document.getElementById('cipher-explainer-skip');
    return !!(stage && caption);
  }

  function clearStage() {
    if (currentTeardown) {
      try { currentTeardown(); } catch (e) { /* ignore */ }
      currentTeardown = null;
    }
    while (stage.firstChild) stage.removeChild(stage.firstChild);
  }

  function cancelAllPending() {
    for (var i = 0; i < pending.length; i++) {
      try { pending[i](); } catch (e) { /* ignore */ }
    }
    pending = [];
  }

  function defer(fn, ms) {
    if (REDUCED) {
      try { fn(); } catch (e) { /* ignore */ }
      return;
    }
    var id = setTimeout(function () {
      fn();
    }, ms);
    pending.push(function () { clearTimeout(id); });
  }

  function timer(durMs, onTick, onDone) {
    if (REDUCED) {
      try { onTick && onTick(1); } catch (e) { /* ignore */ }
      try { onDone && onDone(); } catch (e) { /* ignore */ }
      return { cancel: function () {} };
    }
    var start = null;
    var cancelled = false;
    function frame(ts) {
      if (cancelled) return;
      if (start === null) start = ts;
      var t = Math.min(1, (ts - start) / durMs);
      try { onTick(t); } catch (e) { /* ignore */ }
      if (t < 1) requestAnimationFrame(frame);
      else { try { onDone && onDone(); } catch (e) { /* ignore */ } }
    }
    requestAnimationFrame(frame);
    var handle = { cancel: function () { cancelled = true; } };
    pending.push(function () { handle.cancel(); });
    return handle;
  }

  function pulse(parent, x, y, color, options) {
    if (REDUCED) return;
    options = options || {};
    var r0 = options.r0 != null ? options.r0 : 14;
    var r1 = options.r1 != null ? options.r1 : 33;
    var dur = options.dur || 1400;
    var ring = el(
      'circle',
      {
        cx: x,
        cy: y,
        r: r0,
        fill: 'none',
        stroke: color || COL.accent,
        'stroke-width': 2,
        opacity: 0.65
      },
      parent
    );
    timer(dur, function (t) {
      ring.setAttribute('r', r0 + (r1 - r0) * easeOut(t));
      ring.setAttribute('opacity', 0.65 * (1 - t));
    }, function () {
      if (ring.parentNode) ring.parentNode.removeChild(ring);
    });
  }

  function setCaption(html) {
    if (!caption) return;
    if (REDUCED) {
      caption.innerHTML = html;
      caption.style.opacity = '1';
      return;
    }
    caption.style.transition = 'opacity 180ms ease';
    caption.style.opacity = '0';
    var id = setTimeout(function () {
      caption.innerHTML = html;
      caption.style.opacity = '1';
    }, 200);
    pending.push(function () { clearTimeout(id); });
  }

  function sumDurations(from, to) {
    var n = 0;
    for (var i = from; i < to; i++) n += SCENES[i].duration;
    return n;
  }

  function totalDuration() {
    return sumDurations(0, SCENES.length);
  }

  function sceneAtX(px) {
    if (!progressTrack) return 0;
    var rect = progressTrack.getBoundingClientRect();
    var ratio = Math.max(0, Math.min(1, (px - rect.left) / rect.width));
    var target = ratio * totalDuration();
    var n = 0;
    for (var i = 0; i < SCENES.length; i++) {
      n += SCENES[i].duration;
      if (target <= n) return i;
    }
    return SCENES.length - 1;
  }

  function show(i) {
    if (i < 0) i = 0;
    if (i >= SCENES.length) {
      paintEndCard();
      return;
    }
    cancelAllPending();
    clearStage();
    idx = i;
    if (sceneLabel) sceneLabel.textContent = SCENES[i].label || '';
    setCaption(SCENES[i].caption || '');
    sceneStart = performance.now();
    elapsedInPaused = 0;
    var teardown = null;
    try {
      teardown = SCENES[i].paint(stage);
    } catch (e) {
      console.error('cinematic paint error', e);
    }
    currentTeardown = typeof teardown === 'function' ? teardown : null;
  }

  function tick() {
    if (paused) {
      rafId = requestAnimationFrame(tick);
      return;
    }
    var elapsed = performance.now() - sceneStart;
    var total = sumDurations(0, idx) + Math.min(elapsed, SCENES[idx].duration);
    var ratio = total / totalDuration();
    if (progressFill) progressFill.style.width = 100 * ratio + '%';
    if (progressHead) {
      progressHead.style.left = 100 * ratio + '%';
    }
    if (elapsed >= SCENES[idx].duration) {
      if (idx < SCENES.length - 1) {
        show(idx + 1);
      } else {
        paintEndCard();
        return;
      }
    }
    rafId = requestAnimationFrame(tick);
  }

  function paintEndCard() {
    cancelAllPending();
    if (progressFill) progressFill.style.width = '100%';
    if (progressHead) progressHead.style.left = '100%';
    if (currentTeardown) {
      try { currentTeardown(); } catch (e) { /* ignore */ }
      currentTeardown = null;
    }
    if (typeof window.cipherPaintBrandEndCard === 'function') {
      window.cipherPaintBrandEndCard(stage);
    }
  }

  function setPaused(p) {
    paused = p;
    if (pauseBtn) pauseBtn.textContent = p ? 'play' : 'pause';
    if (!p) {
      sceneStart = performance.now() - elapsedInPaused;
    } else {
      elapsedInPaused = performance.now() - sceneStart;
    }
  }

  function wireControls() {
    if (pauseBtn) {
      pauseBtn.addEventListener('click', function () { setPaused(!paused); });
    }
    if (replayBtn) {
      replayBtn.addEventListener('click', function () {
        setPaused(false);
        show(0);
      });
    }
    if (skipBtn) {
      skipBtn.addEventListener('click', function () {
        if (idx < SCENES.length - 1) show(idx + 1);
        else paintEndCard();
      });
    }

    if (progressTrack) {
      progressTrack.style.cursor = 'pointer';
      progressTrack.addEventListener('mousedown', function (e) {
        dragging = true;
        var target = sceneAtX(e.clientX);
        show(target);
      });
      document.addEventListener('mousemove', function (e) {
        var rect = progressTrack.getBoundingClientRect();
        if (e.clientX >= rect.left && e.clientX <= rect.right) {
          var sIdx = sceneAtX(e.clientX);
          if (progressTooltip) {
            progressTooltip.textContent = SCENES[sIdx] ? SCENES[sIdx].label : '';
            progressTooltip.style.opacity = '1';
            var ratio = (e.clientX - rect.left) / rect.width;
            progressTooltip.style.left = (100 * ratio) + '%';
          }
        } else if (progressTooltip) {
          progressTooltip.style.opacity = '0';
        }
        if (dragging) {
          var target = sceneAtX(e.clientX);
          if (target !== idx) show(target);
        }
      });
      document.addEventListener('mouseup', function () {
        dragging = false;
      });
      progressTrack.addEventListener('mouseleave', function () {
        if (progressTooltip) progressTooltip.style.opacity = '0';
      });
    }

    document.addEventListener('keydown', function (e) {
      if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) return;
      if (e.code === 'Space') {
        e.preventDefault();
        setPaused(!paused);
      } else if (e.code === 'ArrowRight') {
        if (idx < SCENES.length - 1) show(idx + 1);
      } else if (e.code === 'ArrowLeft') {
        if (idx > 0) show(idx - 1);
      } else if (e.key === 'r' || e.key === 'R') {
        setPaused(false);
        show(0);
      }
    });

    document.addEventListener('visibilitychange', function () {
      if (document.hidden && !paused) {
        setPaused(true);
      }
    });
  }

  /*
   * Public entry point. Per-cinematic JS calls:
   *
   *   cipherCinematic.run({ scenes: [ ... ] });
   *
   * The engine binds DOM, paints the scene markers on the progress bar,
   * wires controls, and starts the runtime loop.
   */
  window.cipherCinematic = {
    SVG_NS: SVG_NS,
    REDUCED: REDUCED,
    COL: COL,
    el: el,
    text: text,
    easeInOut: easeInOut,
    easeOut: easeOut,
    pulse: pulse,
    defer: defer,
    timer: timer,
    setCaption: setCaption,
    run: function (cfg) {
      if (!cfg || !cfg.scenes || !cfg.scenes.length) return;
      if (!bind()) return;

      SCENES = cfg.scenes;

      // Scene markers on the track so the viewer sees chapter divisions.
      if (progressTrack) {
        var total = totalDuration();
        var sum = 0;
        var existing = progressTrack.querySelectorAll('.cipher-marker');
        for (var k = 0; k < existing.length; k++) {
          existing[k].parentNode.removeChild(existing[k]);
        }
        for (var i = 0; i < SCENES.length - 1; i++) {
          sum += SCENES[i].duration;
          var marker = document.createElement('span');
          marker.className = 'cipher-marker';
          marker.style.position = 'absolute';
          marker.style.left = (100 * sum / total) + '%';
          marker.style.top = '0';
          marker.style.width = '2px';
          marker.style.height = '100%';
          marker.style.background = 'rgba(255,255,255,0.4)';
          marker.style.pointerEvents = 'none';
          progressTrack.appendChild(marker);
        }
      }

      wireControls();
      show(0);
      rafId = requestAnimationFrame(tick);
    }
  };
})();
