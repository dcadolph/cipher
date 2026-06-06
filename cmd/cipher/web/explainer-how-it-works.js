/*
 * explainer-how-it-works.js
 *
 * Mechanism walkthrough: how cipher (and sops underneath) encrypts a
 * file end to end. Six scenes, ~80 s total. Scene paint functions are
 * re-entrant.
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

  function chip(parent, x, y, w, h, label, sub, kind) {
    var fill =
      kind === 'accent' ? 'rgba(249,99,2,0.14)' :
      kind === 'success' ? 'rgba(90,201,148,0.14)' :
      kind === 'vault' ? 'rgba(126,169,255,0.14)' :
      kind === 'critical' ? 'rgba(240,98,98,0.14)' :
      'rgba(255,255,255,0.05)';
    var stroke =
      kind === 'accent' ? 'rgba(249,99,2,0.55)' :
      kind === 'success' ? 'rgba(90,201,148,0.55)' :
      kind === 'vault' ? 'rgba(126,169,255,0.55)' :
      kind === 'critical' ? 'rgba(240,98,98,0.55)' :
      'rgba(255,255,255,0.18)';
    var g = el('g', { transform: 'translate(' + x + ' ' + y + ')' }, parent);
    el('rect', { x: 0, y: 0, width: w, height: h, rx: 10, fill: fill, stroke: stroke, 'stroke-width': 1 }, g);
    text(g, w / 2, h / 2 + 4, label, { fill: COL.text, anchor: 'middle', size: 15, weight: 700 });
    if (sub) {
      text(g, w / 2, h - 9, sub, { fill: COL.muted, anchor: 'middle', size: 11 });
    }
    return g;
  }

  function fadeIn(node, ms, delay) {
    node.setAttribute('opacity', 0);
    defer(function () {
      timer(ms, function (t) { node.setAttribute('opacity', easeOut(t)); });
    }, delay || 0);
  }

  function arrow(parent, x1, y1, x2, y2, color, id) {
    var defs = el('defs', null, parent);
    var mk = el('marker', {
      id: id, viewBox: '0 0 12 12', refX: 10, refY: 6,
      markerWidth: 8, markerHeight: 8, orient: 'auto'
    }, defs);
    el('path', { d: 'M 0 0 L 12 6 L 0 12 z', fill: color }, mk);
    return el('path', {
      d: 'M ' + x1 + ' ' + y1 + ' L ' + x2 + ' ' + y2,
      stroke: color, 'stroke-width': 3, fill: 'none',
      'marker-end': 'url(#' + id + ')'
    }, parent);
  }

  function key(parent, x, y, color, label) {
    var g = el('g', { transform: 'translate(' + x + ' ' + y + ')' }, parent);
    el('circle', { cx: 18, cy: 18, r: 14, fill: 'none', stroke: color, 'stroke-width': 4 }, g);
    el('rect', { x: 14, y: 28, width: 8, height: 30, rx: 1, fill: color }, g);
    el('rect', { x: 22, y: 40, width: 10, height: 4, fill: color }, g);
    el('rect', { x: 22, y: 50, width: 14, height: 4, fill: color }, g);
    if (label) {
      text(g, 22, 80, label, { fill: COL.muted, anchor: 'middle', size: 11 });
    }
    return g;
  }

  /* ---------- Scene 1: plaintext file ---------- */
  function scene1(stage) {
    text(stage, 550, 100, 'step 1: a yaml file with one secret', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 3, weight: 600
    });

    var file = el('g', { transform: 'translate(280 170)', opacity: 0 }, stage);
    panel(file, 0, 0, 540, 250);
    el('circle', { cx: 16, cy: 14, r: 4, fill: '#f06262' }, file);
    el('circle', { cx: 30, cy: 14, r: 4, fill: '#f9b342' }, file);
    el('circle', { cx: 44, cy: 14, r: 4, fill: '#5ac994' }, file);
    var lines = [
      ['# prod.yaml', COL.muted],
      ['service:', COL.text],
      ['  name: payments', COL.body],
      ['  region: us-east-1', COL.body],
      ['  secret_key: hunter2-real-key', '#f06262']
    ];
    for (var i = 0; i < lines.length; i++) {
      text(file, 22, 50 + i * 28, lines[i][0], {
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        size: 14, fill: lines[i][1]
      });
    }
    fadeIn(file, 700, 0);

    var note = text(stage, 550, 470, 'cipher receives this as a byte slice plus the path.', {
      fill: COL.text, anchor: 'middle', size: 18, weight: 700, opacity: 0
    });
    fadeIn(note, 500, 1200);
  }

  /* ---------- Scene 2: data key generation ---------- */
  function scene2(stage) {
    text(stage, 550, 100, 'step 2: cipher generates a fresh data key', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 3, weight: 600
    });

    var dice = el('g', { transform: 'translate(180 220)', opacity: 0 }, stage);
    chip(dice, 0, 0, 220, 90, 'csprng', 'crypto/rand', 'accent');
    fadeIn(dice, 600, 0);

    var arr = el('g', { opacity: 0 }, stage);
    arrow(arr, 410, 265, 530, 265, COL.accent, 'arrow-genkey-hiw');
    fadeIn(arr, 400, 800);

    var dk = el('g', { transform: 'translate(540 220)', opacity: 0 }, stage);
    key(dk, 50, 0, COL.accent, 'data key');
    text(dk, 50, 110, 'AES-256 (random)', { fill: COL.body, anchor: 'middle', size: 12, family: 'ui-monospace, SFMono-Regular, Menlo, monospace' });
    fadeIn(dk, 600, 1300);

    var caption = text(stage, 550, 430, 'every file gets its own data key. nothing reused.', {
      fill: COL.text, anchor: 'middle', size: 18, weight: 700, opacity: 0
    });
    fadeIn(caption, 500, 1900);
  }

  /* ---------- Scene 3: encrypt values, leave structure ---------- */
  function scene3(stage) {
    text(stage, 550, 90, 'step 3: encrypt values, keep the structure', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 3, weight: 600
    });

    var before = el('g', { transform: 'translate(80 150)', opacity: 0 }, stage);
    panel(before, 0, 0, 380, 220);
    text(before, 22, 38, '# plaintext', { family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 13, fill: COL.muted });
    var bl = [
      'service:',
      '  name: payments',
      '  region: us-east-1',
      '  secret_key: hunter2-real-key'
    ];
    for (var i = 0; i < bl.length; i++) {
      text(before, 22, 70 + i * 26, bl[i], { family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 13, fill: i === 3 ? '#f06262' : COL.body });
    }
    fadeIn(before, 600, 0);

    var ar = el('g', { opacity: 0 }, stage);
    arrow(ar, 480, 260, 620, 260, COL.accent, 'arrow-enc-hiw');
    text(ar, 550, 250, 'AES-GCM', { fill: COL.accent, anchor: 'middle', size: 12, weight: 700 });
    fadeIn(ar, 400, 1000);

    var after = el('g', { transform: 'translate(640 150)', opacity: 0 }, stage);
    panel(after, 0, 0, 400, 220, { stroke: 'rgba(90,201,148,0.4)' });
    text(after, 22, 38, '# encrypted', { family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 13, fill: COL.muted });
    var al = [
      ['service:', COL.body],
      ['  name: payments', COL.body],
      ['  region: us-east-1', COL.body],
      ['  secret_key: ENC[AES256_GCM,...]', '#5ac994']
    ];
    for (var j = 0; j < al.length; j++) {
      text(after, 22, 70 + j * 26, al[j][0], { family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 13, fill: al[j][1] });
    }
    fadeIn(after, 700, 1500);

    var caption = text(stage, 550, 420, 'keys, indentation, and comments survive untouched.', {
      fill: COL.text, anchor: 'middle', size: 18, weight: 700, opacity: 0
    });
    fadeIn(caption, 500, 2400);
  }

  /* ---------- Scene 4: wrap the data key per recipient ---------- */
  function scene4(stage) {
    text(stage, 550, 90, 'step 4: wrap the data key for every recipient', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 3, weight: 600
    });

    var dk = el('g', { transform: 'translate(500 130)', opacity: 0 }, stage);
    key(dk, 0, 0, COL.accent, 'data key');
    fadeIn(dk, 500, 0);

    var recipients = [
      { x: 150, y: 320, color: COL.success, label: 'age', sub: 'age1qy...' },
      { x: 470, y: 320, color: COL.vault, label: 'AWS KMS', sub: 'arn:aws:kms:...' },
      { x: 790, y: 320, color: COL.registry, label: 'GCP KMS', sub: 'projects/p/...' }
    ];
    for (var i = 0; i < recipients.length; i++) {
      (function (r, idx) {
        var grp = el('g', { transform: 'translate(' + r.x + ' ' + r.y + ')', opacity: 0 }, stage);
        chip(grp, 0, 0, 160, 80, r.label, r.sub, idx === 0 ? 'success' : 'vault');
        fadeIn(grp, 500, 700 + idx * 400);

        var arrowGrp = el('g', { opacity: 0 }, stage);
        arrow(arrowGrp, 540, 220, r.x + 80, r.y, r.color, 'arrow-wrap-' + idx);
        fadeIn(arrowGrp, 400, 900 + idx * 400);

        var sealed = el('g', { transform: 'translate(' + (r.x + 30) + ' ' + (r.y + 110) + ')', opacity: 0 }, stage);
        el('rect', { x: 0, y: 0, width: 100, height: 36, rx: 6, fill: 'rgba(10,12,18,0.92)', stroke: r.color, 'stroke-width': 1 }, sealed);
        text(sealed, 50, 23, 'ENC[' + r.label + ']', { family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 11, fill: r.color, anchor: 'middle' });
        fadeIn(sealed, 500, 1400 + idx * 400);
      })(recipients[i], i);
    }

    var caption = text(stage, 550, 510, 'any one recipient can unwrap. any one can decrypt the file.', {
      fill: COL.text, anchor: 'middle', size: 18, weight: 700, opacity: 0
    });
    fadeIn(caption, 500, 3000);
  }

  /* ---------- Scene 5: emit envelope ---------- */
  function scene5(stage) {
    text(stage, 550, 90, 'step 5: emit one self-contained file', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 3, weight: 600
    });

    var env = el('g', { transform: 'translate(180 150)', opacity: 0 }, stage);
    panel(env, 0, 0, 740, 340, { stroke: 'rgba(90,201,148,0.4)' });
    el('circle', { cx: 16, cy: 14, r: 4, fill: '#f06262' }, env);
    el('circle', { cx: 30, cy: 14, r: 4, fill: '#f9b342' }, env);
    el('circle', { cx: 44, cy: 14, r: 4, fill: '#5ac994' }, env);
    text(env, 22, 50, '# prod.yaml', { family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 13, fill: COL.muted });
    var lines = [
      ['service:', COL.body],
      ['  name: payments', COL.body],
      ['  region: us-east-1', COL.body],
      ['  secret_key: ENC[AES256_GCM,data:Lp9d..]', '#5ac994'],
      ['sops:', COL.muted],
      ['  age:', COL.body],
      ['    - recipient: age1qy...', COL.body],
      ['      enc: |-', COL.body],
      ['        -----BEGIN AGE ENCRYPTED FILE-----', COL.body],
      ['  kms:', COL.body],
      ['    - arn: arn:aws:kms:...', COL.body],
      ['  mac: ENC[AES256_GCM,...]', COL.body]
    ];
    for (var i = 0; i < lines.length; i++) {
      text(env, 22, 78 + i * 20, lines[i][0], { family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 12, fill: lines[i][1] });
    }
    fadeIn(env, 800, 0);

    var caption = text(stage, 550, 540, 'this file is the only thing in git. everything to decrypt is inside it.', {
      fill: COL.text, anchor: 'middle', size: 18, weight: 700, opacity: 0
    });
    fadeIn(caption, 500, 1800);
  }

  /* ---------- Scene 6: decrypt round trip ---------- */
  function scene6(stage) {
    text(stage, 550, 90, 'step 6: decrypt is the same machinery in reverse', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 3, weight: 600
    });

    var env = el('g', { transform: 'translate(80 200)', opacity: 0 }, stage);
    chip(env, 0, 0, 230, 80, 'prod.yaml', 'encrypted envelope', 'success');
    fadeIn(env, 500, 0);

    var ar1 = el('g', { opacity: 0 }, stage);
    arrow(ar1, 330, 240, 460, 240, COL.accent, 'arrow-dec1-hiw');
    text(ar1, 395, 232, 'unwrap', { fill: COL.accent, anchor: 'middle', size: 12, weight: 700 });
    fadeIn(ar1, 400, 800);

    var dk = el('g', { transform: 'translate(470 200)', opacity: 0 }, stage);
    key(dk, 0, 0, COL.accent, 'data key');
    fadeIn(dk, 500, 1200);

    var ar2 = el('g', { opacity: 0 }, stage);
    arrow(ar2, 580, 240, 720, 240, COL.accent, 'arrow-dec2-hiw');
    text(ar2, 650, 232, 'AES-GCM', { fill: COL.accent, anchor: 'middle', size: 12, weight: 700 });
    fadeIn(ar2, 400, 1700);

    var out = el('g', { transform: 'translate(730 200)', opacity: 0 }, stage);
    chip(out, 0, 0, 250, 80, 'prod.yaml', 'plaintext (in memory)', 'accent');
    fadeIn(out, 500, 2100);

    var caption = text(stage, 550, 430, 'pick one identity. one call. plaintext in memory.', {
      fill: COL.text, anchor: 'middle', size: 18, weight: 700, opacity: 0
    });
    fadeIn(caption, 500, 2600);

    var sub = text(stage, 550, 462, 'no plaintext ever lands on disk. cipher hands it back as a byte slice.', {
      fill: COL.muted, anchor: 'middle', size: 13, opacity: 0
    });
    fadeIn(sub, 500, 3000);
  }

  /* ---------- the SCENES array ---------- */
  var SCENES = [
    {
      label: '1 / 6 . input',
      duration: 9000,
      caption:
        "Start with a plain <span class='accent'>YAML file</span> on disk." +
        "<br/><span class='sub'>cipher takes the bytes plus the path; path drives format.</span>",
      paint: scene1
    },
    {
      label: '2 / 6 . fresh key',
      duration: 10000,
      caption:
        "cipher rolls a <span class='accent'>fresh AES data key</span> from crypto/rand." +
        "<br/><span class='sub'>Per-file. Never reused. The recipients never see this directly.</span>",
      paint: scene2
    },
    {
      label: '3 / 6 . encrypt values',
      duration: 12000,
      caption:
        "<span class='accent'>AES-GCM</span> encrypts every leaf value in place." +
        "<br/><span class='sub'>Keys and structure stay readable. PR diffs still work.</span>",
      paint: scene3
    },
    {
      label: '4 / 6 . wrap key',
      duration: 14000,
      caption:
        "Wrap the data key for <span class='accent'>each recipient</span>." +
        "<br/><span class='sub'>age. KMS. GCP. Vault. Azure KV. Mix and match per file.</span>",
      paint: scene4
    },
    {
      label: '5 / 6 . envelope',
      duration: 12000,
      caption:
        "Everything ships in a <span class='accent'>single YAML envelope</span>." +
        "<br/><span class='sub'>Ciphertext, wrapped keys, MAC, version. Self-contained.</span>",
      paint: scene5
    },
    {
      label: '6 / 6 . decrypt',
      duration: 12500,
      caption:
        "Decrypt is <span class='accent'>the same in reverse</span>." +
        "<br/><span class='sub'>Unwrap with any one identity. AES-GCM the values. Plaintext returned.</span>",
      paint: scene6
    }
  ];

  C.run({ scenes: SCENES });
})();
