/*
 * explainer-intro.js
 *
 * "What is cipher" for first-time visitors who may not know sops.
 * Five short scenes, total runtime ~60 s. Paint functions are
 * re-entrant: scrubbing into the middle of a scene repaints from
 * scratch.
 */
(function () {
  var C = window.cipherCinematic;
  if (!C) return;
  var el = C.el;
  var text = C.text;
  var COL = C.COL;
  var timer = C.timer;
  var defer = C.defer;
  var easeOut = C.easeOut;

  /* ---------- shared primitives ---------- */

  function panel(parent, x, y, w, h, opts) {
    opts = opts || {};
    return el('rect', {
      x: x, y: y, width: w, height: h, rx: opts.rx || 12,
      fill: opts.fill || 'rgba(10,12,18,0.92)',
      stroke: opts.stroke || 'rgba(255,255,255,0.08)',
      'stroke-width': opts.strokeWidth || 1
    }, parent);
  }

  function code(parent, x, y, lines, opts) {
    opts = opts || {};
    var pad = 18;
    var lineH = 22;
    var w = opts.w || 520;
    var h = pad * 2 + lines.length * lineH;
    var g = el('g', { transform: 'translate(' + x + ' ' + y + ')' }, parent);
    panel(g, 0, 0, w, h);
    el('circle', { cx: 16, cy: 14, r: 4, fill: '#f06262' }, g);
    el('circle', { cx: 30, cy: 14, r: 4, fill: '#f9b342' }, g);
    el('circle', { cx: 44, cy: 14, r: 4, fill: '#5ac994' }, g);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      text(g, pad, pad + 18 + i * lineH, line.t, {
        fill: line.c || COL.body,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        size: 13
      });
    }
    return g;
  }

  function fadeIn(node, ms, delay) {
    node.setAttribute('opacity', 0);
    defer(function () {
      timer(ms, function (t) { node.setAttribute('opacity', easeOut(t)); });
    }, delay || 0);
  }

  /* ---------- Scene 1: title card ---------- */
  function scene1(stage) {
    var halo = el('circle', {
      cx: 550, cy: 290, r: 4, fill: COL.accentSoft
    }, stage);
    timer(900, function (t) {
      halo.setAttribute('r', 4 + 180 * easeOut(t));
    });

    var keyhole = el('g', { transform: 'translate(510 210)', opacity: 0 }, stage);
    el('rect', { x: 0, y: 26, width: 100, height: 112, rx: 12, fill: COL.accent }, keyhole);
    el('circle', { cx: 50, cy: 30, r: 26, fill: 'none', stroke: COL.accent, 'stroke-width': 10 }, keyhole);
    el('rect', { x: 44, y: 68, width: 12, height: 42, rx: 3, fill: '#06090f' }, keyhole);
    timer(700, function (t) { keyhole.setAttribute('opacity', easeOut(t)); });

    var wordmark = text(stage, 550, 430, 'cipher', {
      fill: COL.text, anchor: 'middle', size: 72, weight: 700, opacity: 0
    });
    timer(800, function (t) { wordmark.setAttribute('opacity', easeOut(t)); });

    var sub = text(stage, 550, 480, 'SECRETS IN GIT . WITHOUT THE FOOTGUNS', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 5, opacity: 0
    });
    defer(function () {
      timer(700, function (t) { sub.setAttribute('opacity', 0.85 * easeOut(t)); });
    }, 300);
  }

  /* ---------- Scene 2: secrets in git is hard ---------- */
  function scene2(stage) {
    text(stage, 550, 90, 'the obvious thing fails', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 3, weight: 600
    });

    var bad = code(stage, 130, 150, [
      { t: '# config/prod.yaml', c: COL.muted },
      { t: 'database:', c: COL.text },
      { t: '  host: db.prod.internal', c: COL.body },
      { t: '  password: ' + JSON.stringify('hunter2-real-key'), c: '#f06262' },
      { t: 'stripe_key: ' + JSON.stringify('sk_live_abc123def'), c: '#f06262' }
    ], { w: 420 });
    fadeIn(bad, 600, 0);

    var arrow = el('g', { opacity: 0 }, stage);
    el('path', {
      d: 'M 600 250 L 740 250', stroke: COL.critical, 'stroke-width': 3, fill: 'none',
      'marker-end': 'url(#arrow-crit-intro)'
    }, arrow);
    el('defs', null, arrow);
    var defs = el('defs', null, stage);
    var mk = el('marker', {
      id: 'arrow-crit-intro', viewBox: '0 0 12 12', refX: 10, refY: 6,
      markerWidth: 8, markerHeight: 8, orient: 'auto'
    }, defs);
    el('path', { d: 'M 0 0 L 12 6 L 0 12 z', fill: COL.critical }, mk);
    fadeIn(arrow, 500, 500);

    var bang = el('g', { transform: 'translate(780 200)', opacity: 0 }, stage);
    el('circle', { cx: 50, cy: 50, r: 50, fill: 'rgba(240,98,98,0.18)', stroke: COL.critical, 'stroke-width': 2 }, bang);
    text(bang, 50, 64, '!', { fill: COL.critical, anchor: 'middle', size: 44, weight: 700 });
    fadeIn(bang, 500, 900);

    var caption = text(stage, 550, 400, 'commit the file, leak the secret.', {
      fill: COL.text, anchor: 'middle', size: 22, weight: 700, opacity: 0
    });
    fadeIn(caption, 500, 1400);
    var sub = text(stage, 550, 432, 'git history is forever. rotating after the fact is expensive.', {
      fill: COL.muted, anchor: 'middle', size: 14, opacity: 0
    });
    fadeIn(sub, 500, 1800);
  }

  /* ---------- Scene 3: sops idea ---------- */
  function scene3(stage) {
    text(stage, 550, 90, 'sops idea: encrypt the values, keep the shape', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 3, weight: 600
    });

    var safe = code(stage, 140, 150, [
      { t: '# config/prod.yaml (after sops)', c: COL.muted },
      { t: 'database:', c: COL.text },
      { t: '  host: db.prod.internal', c: COL.body },
      { t: '  password: ENC[AES256_GCM,data:8jk2..]', c: '#5ac994' },
      { t: 'stripe_key: ENC[AES256_GCM,data:Lp9d..]', c: '#5ac994' },
      { t: 'sops:', c: COL.muted },
      { t: '  age: { recipients: age1qy.. }', c: COL.body }
    ], { w: 480 });
    fadeIn(safe, 700, 0);

    var bullets = el('g', { transform: 'translate(680 170)', opacity: 0 }, stage);
    var items = [
      ['structure stays plain', 'keys, indentation, comments diff cleanly'],
      ['values are sealed', 'AES-GCM ciphertext, MAC included'],
      ['data key is wrapped', 'age / KMS / vault hold the unwrap key'],
      ['no plaintext in git', 'review the file like any other YAML']
    ];
    var y = 0;
    for (var i = 0; i < items.length; i++) {
      el('circle', { cx: 6, cy: y + 8, r: 4, fill: COL.accent }, bullets);
      text(bullets, 20, y + 12, items[i][0], { fill: COL.text, size: 15, weight: 700 });
      text(bullets, 20, y + 30, items[i][1], { fill: COL.muted, size: 12 });
      y += 50;
    }
    fadeIn(bullets, 800, 1200);
  }

  /* ---------- Scene 4: cipher in Go ---------- */
  function scene4(stage) {
    text(stage, 550, 90, 'cipher: the Go interface around sops', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 3, weight: 600
    });

    var snippet = code(stage, 130, 150, [
      { t: 'import "github.com/dcadolph/cipher"', c: COL.muted },
      { t: 'import cipherage "github.com/dcadolph/cipher/age"', c: COL.muted },
      { t: '', c: COL.body },
      { t: 'enc := cipher.NewEncoder(', c: COL.text },
      { t: '    cipherage.NewProvider("age1qy..."),', c: COL.body },
      { t: ')', c: COL.text },
      { t: 'out, _ := enc.Encode(ctx, "prod.yaml", plain)', c: COL.text }
    ], { w: 520 });
    fadeIn(snippet, 600, 0);

    var arrows = el('g', { opacity: 0 }, stage);
    el('path', {
      d: 'M 680 320 L 800 320', stroke: COL.accent, 'stroke-width': 3, fill: 'none',
      'marker-end': 'url(#arrow-go-intro)'
    }, arrows);
    var defs = el('defs', null, stage);
    var mk = el('marker', {
      id: 'arrow-go-intro', viewBox: '0 0 12 12', refX: 10, refY: 6,
      markerWidth: 8, markerHeight: 8, orient: 'auto'
    }, defs);
    el('path', { d: 'M 0 0 L 12 6 L 0 12 z', fill: COL.accent }, mk);
    fadeIn(arrows, 400, 900);

    var output = el('g', { transform: 'translate(810 270)', opacity: 0 }, stage);
    panel(output, 0, 0, 200, 100, { stroke: 'rgba(90,201,148,0.4)' });
    text(output, 100, 32, '*.yaml.sops', { fill: COL.success, anchor: 'middle', size: 14, weight: 700, family: 'ui-monospace, SFMono-Regular, Menlo, monospace' });
    text(output, 100, 56, 'AES-GCM payload', { fill: COL.body, anchor: 'middle', size: 11 });
    text(output, 100, 76, 'wrapped data key', { fill: COL.body, anchor: 'middle', size: 11 });
    fadeIn(output, 500, 1300);

    var caption = text(stage, 550, 470, 'one call. defaults handle format, MAC, metadata.', {
      fill: COL.text, anchor: 'middle', size: 18, weight: 700, opacity: 0
    });
    fadeIn(caption, 500, 1800);
  }

  /* ---------- Scene 5: five minutes ---------- */
  function scene5(stage) {
    var headline = text(stage, 550, 200, '5 minutes from "go get" to encrypted commit', {
      fill: COL.text, anchor: 'middle', size: 26, weight: 700, opacity: 0
    });
    fadeIn(headline, 700, 0);

    var steps = el('g', { transform: 'translate(220 250)', opacity: 0 }, stage);
    var items = [
      ['go get github.com/dcadolph/cipher', 'add the module'],
      ['age-keygen -o key.txt', 'create a recipient pair'],
      ['cipher encrypt prod.yaml -i --age age1...', 'encrypt your first file'],
      ['cipher precommit', 'block plaintext at the git door']
    ];
    var y = 0;
    for (var i = 0; i < items.length; i++) {
      el('circle', { cx: 14, cy: y + 18, r: 14, fill: 'rgba(249,99,2,0.18)', stroke: COL.accent, 'stroke-width': 1.5 }, steps);
      text(steps, 14, y + 23, String(i + 1), { fill: COL.accent, anchor: 'middle', size: 14, weight: 700 });
      text(steps, 44, y + 16, items[i][0], { fill: COL.text, size: 14, weight: 700, family: 'ui-monospace, SFMono-Regular, Menlo, monospace' });
      text(steps, 44, y + 34, items[i][1], { fill: COL.muted, size: 12 });
      y += 52;
    }
    fadeIn(steps, 900, 800);

    var cta = text(stage, 550, 540, 'cipher demo opens this browser. four more cinematics from there.', {
      fill: COL.muted, anchor: 'middle', size: 14, opacity: 0
    });
    fadeIn(cta, 500, 2200);
  }

  /* ---------- the SCENES array ---------- */
  var SCENES = [
    {
      label: '1 / 5 . cipher',
      duration: 6500,
      caption:
        "<span class='accent'>cipher</span>" +
        "<br/><span class='sub'>Encrypted secrets in git, without the footguns.</span>",
      paint: scene1
    },
    {
      label: '2 / 5 . the problem',
      duration: 11000,
      caption:
        "Plaintext secrets in version control <span class='accent'>leak forever</span>." +
        "<br/><span class='sub'>Git keeps history. Rotation after exposure is expensive.</span>",
      paint: scene2
    },
    {
      label: '3 / 5 . the sops idea',
      duration: 12500,
      caption:
        "<span class='accent'>sops</span> encrypts the values, leaves the structure." +
        "<br/><span class='sub'>YAML keys and shape diff cleanly. Only secrets become ciphertext.</span>",
      paint: scene3
    },
    {
      label: '4 / 5 . cipher in Go',
      duration: 13500,
      caption:
        "cipher gives sops a <span class='accent'>first-class Go API</span>." +
        "<br/><span class='sub'>One call. Path drives format. Provider drives recipients.</span>",
      paint: scene4
    },
    {
      label: '5 / 5 . start',
      duration: 11500,
      caption:
        "<span class='accent'>go get</span> and you are encrypting in five minutes." +
        "<br/><span class='sub'>Then walk the rest of the library: how it works, walks, recipients, pre-commit.</span>",
      paint: scene5
    }
  ];

  C.run({ scenes: SCENES });
})();
