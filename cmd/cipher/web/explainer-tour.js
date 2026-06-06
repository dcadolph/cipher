/*
 * explainer-tour.js
 *
 * Hero cinematic: cipher in 90 seconds.
 *
 * Eight scenes, total runtime ~90 s. Scene functions are re-entrant:
 * scrubbing into the middle of a scene paints it cleanly from scratch.
 * Per-scene state stays on the stage as appended SVG; the engine
 * clears the stage between scenes.
 */
(function () {
  var C = window.cipherCinematic;
  if (!C) return;
  var el = C.el;
  var text = C.text;
  var COL = C.COL;
  var timer = C.timer;
  var defer = C.defer;
  var pulse = C.pulse;
  var easeOut = C.easeOut;

  /* ---------- shared primitives ---------- */

  function chip(parent, x, y, w, h, kind, label, sub) {
    var g = el('g', { transform: 'translate(' + x + ' ' + y + ')' }, parent);
    var fill =
      kind === 'accent' ? 'rgba(249,99,2,0.14)' :
      kind === 'success' ? 'rgba(90,201,148,0.14)' :
      kind === 'critical' ? 'rgba(240,98,98,0.14)' :
      'rgba(255,255,255,0.05)';
    var stroke =
      kind === 'accent' ? 'rgba(249,99,2,0.55)' :
      kind === 'success' ? 'rgba(90,201,148,0.55)' :
      kind === 'critical' ? 'rgba(240,98,98,0.55)' :
      'rgba(255,255,255,0.12)';
    el('rect', {
      x: 0, y: 0, width: w, height: h, rx: 10, ry: 10,
      fill: fill, stroke: stroke, 'stroke-width': 1
    }, g);
    text(g, w / 2, h / 2 + 5, label, {
      fill: COL.text, anchor: 'middle', size: 16, weight: 700
    });
    if (sub) {
      text(g, w / 2, h - 8, sub, {
        fill: COL.muted, anchor: 'middle', size: 11, weight: 400
      });
    }
    return g;
  }

  function code(parent, x, y, lines, opts) {
    opts = opts || {};
    var pad = 18;
    var lineH = 22;
    var w = opts.w || 540;
    var h = pad * 2 + lines.length * lineH;
    var g = el('g', { transform: 'translate(' + x + ' ' + y + ')' }, parent);
    el('rect', {
      x: 0, y: 0, width: w, height: h, rx: 10, ry: 10,
      fill: 'rgba(10,12,18,0.92)',
      stroke: 'rgba(255,255,255,0.08)', 'stroke-width': 1
    }, g);
    // window dots
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

  function arrow(parent, x1, y1, x2, y2, color) {
    var c = color || COL.accent;
    el('path', {
      d: 'M ' + x1 + ' ' + y1 + ' L ' + x2 + ' ' + y2,
      stroke: c, 'stroke-width': 2, fill: 'none',
      'marker-end': 'url(#cipher-arrow-' + c.replace(/[^a-z0-9]/gi, '') + ')'
    }, parent);
  }

  function defs(parent) {
    var d = el('defs', {}, parent);
    var marker = el('marker', {
      id: 'cipher-arrow-' + COL.accent.replace(/[^a-z0-9]/gi, ''),
      viewBox: '0 0 10 10', refX: 9, refY: 5,
      markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse'
    }, d);
    el('path', { d: 'M 0 0 L 10 5 L 0 10 z', fill: COL.accent }, marker);
    return d;
  }

  function fileIcon(parent, x, y, kind, label) {
    var g = el('g', { transform: 'translate(' + x + ' ' + y + ')' }, parent);
    var color = kind === 'locked' ? COL.success : kind === 'flagged' ? COL.critical : COL.muted;
    el('path', {
      d: 'M 0 0 L 44 0 L 60 18 L 60 76 L 0 76 Z',
      fill: 'rgba(13,19,32,0.85)', stroke: color, 'stroke-width': 1.5
    }, g);
    el('path', {
      d: 'M 44 0 L 44 18 L 60 18',
      fill: 'none', stroke: color, 'stroke-width': 1.5
    }, g);
    if (kind === 'locked') {
      // lock icon
      el('rect', { x: 22, y: 38, width: 18, height: 14, rx: 2, fill: COL.success }, g);
      el('path', {
        d: 'M 25 38 L 25 32 a 6 6 0 0 1 12 0 L 37 38',
        fill: 'none', stroke: COL.success, 'stroke-width': 2
      }, g);
    } else if (kind === 'flagged') {
      text(g, 30, 50, '!', { fill: COL.critical, anchor: 'middle', size: 22, weight: 700 });
    }
    if (label) {
      text(g, 30, 92, label, { fill: COL.muted, anchor: 'middle', size: 10 });
    }
    return g;
  }

  /* ---------- Scene 1: title card ---------- */
  function scene1(stage) {
    defs(stage);
    // halo
    var halo = el('circle', {
      cx: 550, cy: 280, r: 6, fill: COL.accentSoft
    }, stage);
    timer(900, function (t) {
      halo.setAttribute('r', 6 + 160 * easeOut(t));
    });

    // keyhole mark
    var g = el('g', { transform: 'translate(510 200)', opacity: 0 }, stage);
    el('rect', { x: 0, y: 26, width: 100, height: 112, rx: 12, fill: COL.accent }, g);
    el('circle', { cx: 50, cy: 30, r: 26, fill: 'none', stroke: COL.accent, 'stroke-width': 10 }, g);
    el('rect', { x: 44, y: 68, width: 12, height: 42, rx: 3, fill: '#06090f' }, g);
    timer(700, function (t) { g.setAttribute('opacity', easeOut(t)); });

    var w = text(stage, 550, 420, 'cipher', {
      fill: COL.text, anchor: 'middle', size: 72, weight: 700, opacity: 0
    });
    timer(800, function (t) { w.setAttribute('opacity', easeOut(t)); });

    var tag = text(stage, 550, 470, 'PROGRAMMATIC . SOPS . FROM GO', {
      fill: COL.muted, anchor: 'middle', size: 16, tracking: 5, opacity: 0
    });
    defer(function () {
      timer(700, function (t) { tag.setAttribute('opacity', 0.85 * easeOut(t)); });
    }, 300);
  }

  /* ---------- Scene 2: the gap ---------- */
  function scene2(stage) {
    defs(stage);

    text(stage, 550, 100, 'sops, the upstream Go API', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 3, weight: 600
    });

    // good side
    var good = el('g', { transform: 'translate(150 160)', opacity: 0 }, stage);
    text(good, 0, 0, 'STABLE', { fill: COL.success, size: 12, tracking: 4, weight: 700 });
    chip(good, 0, 16, 320, 64, 'success', 'decrypt.File / decrypt.Data', 'Public. Stable. Documented.');
    timer(500, function (t) { good.setAttribute('opacity', easeOut(t)); });

    // bad side
    var bad = el('g', { transform: 'translate(630 160)', opacity: 0 }, stage);
    text(bad, 0, 0, 'NOT STABLE', { fill: COL.critical, size: 12, tracking: 4, weight: 700 });
    chip(bad, 0, 16, 320, 64, 'critical', 'encrypt.File', 'Not part of the stable surface.');
    defer(function () {
      timer(500, function (t) { bad.setAttribute('opacity', easeOut(t)); });
    }, 600);

    // the boilerplate
    var bp = el('g', { transform: 'translate(280 280)', opacity: 0 }, stage);
    code(bp, 0, 0, [
      { t: 'tree := sops.Tree{Branches: ...}', c: COL.body },
      { t: 'tree.GenerateDataKeyWithKeyServices(...)', c: COL.body },
      { t: 'common.EncryptTree(common.EncryptTreeOpts{...})', c: COL.body },
      { t: 'store.EmitEncryptedFile(tree)', c: COL.body },
      { t: '// ~50 lines, copy-pasted from issue #1094', c: COL.muted }
    ], { w: 540 });
    defer(function () {
      timer(700, function (t) { bp.setAttribute('opacity', easeOut(t)); });
    }, 1200);

    // pointer
    defer(function () {
      var p = el('text', {
        x: 550, y: 555, fill: COL.accent,
        'font-size': 16, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      p.textContent = 'cipher absorbs all of this';
      timer(600, function (t) { p.setAttribute('opacity', easeOut(t)); });
    }, 2400);
  }

  /* ---------- Scene 3: the four interfaces ---------- */
  function scene3(stage) {
    defs(stage);
    text(stage, 550, 80, 'FOUR SINGLE-METHOD INTERFACES', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    var boxes = [
      { name: 'Encoder',     sig: 'Encode(ctx, path, data) ([]byte, error)' },
      { name: 'Decoder',     sig: 'Decode(ctx, path, data) ([]byte, error)' },
      { name: 'KeyProvider', sig: 'KeyGroups(ctx) ([]sops.KeyGroup, error)' },
      { name: 'FileMatcher', sig: 'Match(path) bool' }
    ];
    var startX = 90, gapX = 250, y = 200;
    for (var i = 0; i < boxes.length; i++) {
      (function (i) {
        var g = el('g', {
          transform: 'translate(' + (startX + i * gapX) + ' ' + y + ')',
          opacity: 0
        }, stage);
        el('rect', {
          x: 0, y: 0, width: 220, height: 110, rx: 12,
          fill: 'rgba(13,19,32,0.92)',
          stroke: COL.accent, 'stroke-width': 1
        }, g);
        text(g, 110, 38, boxes[i].name, {
          fill: COL.text, anchor: 'middle', size: 22, weight: 700
        });
        text(g, 110, 76, boxes[i].sig, {
          fill: COL.muted, anchor: 'middle', size: 11,
          family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
        });
        defer(function () {
          timer(500, function (t) { g.setAttribute('opacity', easeOut(t)); });
        }, 200 + i * 300);
      })(i);
    }

    defer(function () {
      var note = el('text', {
        x: 550, y: 380, fill: COL.text,
        'font-size': 18, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      note.textContent = 'Each one has a Func adapter, the http.HandlerFunc style.';
      timer(600, function (t) { note.setAttribute('opacity', easeOut(t)); });
    }, 1700);

    defer(function () {
      var ex = el('g', { transform: 'translate(280 420)', opacity: 0 }, stage);
      code(ex, 0, 0, [
        { t: 'enc := cipher.EncoderFunc(func(ctx, path, data) ([]byte, error) {', c: COL.body },
        { t: '    return doSomething(data), nil', c: COL.body },
        { t: '})', c: COL.body }
      ], { w: 540 });
      timer(500, function (t) { ex.setAttribute('opacity', easeOut(t)); });
    }, 2300);
  }

  /* ---------- Scene 4: encrypt in one line ---------- */
  function scene4(stage) {
    defs(stage);
    text(stage, 550, 80, 'ENCRYPT', {
      fill: COL.accent, anchor: 'middle', size: 14, tracking: 6, weight: 700
    });

    var c = el('g', { transform: 'translate(160 130)', opacity: 0 }, stage);
    code(c, 0, 0, [
      { t: 'ctx := context.Background()', c: COL.body },
      { t: 'enc := cipher.NewEncoder(', c: COL.body },
      { t: '    age.NewProvider("age1qyqsz..."),', c: '#7ea9ff' },
      { t: ')', c: COL.body },
      { t: '', c: COL.body },
      { t: 'ciphertext, err := enc.Encode(', c: COL.body },
      { t: '    ctx, "secrets.yaml", plain,', c: COL.body },
      { t: ')', c: COL.body }
    ], { w: 780 });
    timer(500, function (t) { c.setAttribute('opacity', easeOut(t)); });

    // plain -> cipher pipe
    defer(function () {
      var g = el('g', { transform: 'translate(140 380)', opacity: 0 }, stage);
      chip(g, 0, 0, 200, 64, '', 'plain', 'foo: bar');
      el('path', {
        d: 'M 210 32 L 410 32',
        stroke: COL.accent, 'stroke-width': 2, fill: 'none',
        'stroke-dasharray': '6 6'
      }, g);
      text(g, 310, 22, 'Encode', { fill: COL.accent, anchor: 'middle', size: 12, tracking: 4, weight: 700 });
      chip(g, 420, 0, 380, 64, 'accent', 'ENC[AES-GCM]', 'sops metadata + wrapped data key');
      timer(700, function (t) { g.setAttribute('opacity', easeOut(t)); });
    }, 1000);

    defer(function () {
      var n = el('text', {
        x: 550, y: 520, fill: COL.text,
        'font-size': 20, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'That is the whole encrypt path.';
      timer(500, function (t) { n.setAttribute('opacity', easeOut(t)); });
    }, 2200);
  }

  /* ---------- Scene 5: walks ---------- */
  function scene5(stage) {
    defs(stage);
    text(stage, 550, 70, 'WALK A DIRECTORY', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    // tree on the left
    var tree = el('g', { transform: 'translate(110 130)' }, stage);
    text(tree, 0, 0, './secrets', { fill: COL.text, size: 16, weight: 700 });
    var rows = ['db.yaml', 'tls.yaml', 'sso.yaml', 'oauth.yaml', 'kv.json', 'redis.ini'];
    var fileNodes = [];
    for (var i = 0; i < rows.length; i++) {
      (function (i) {
        var g = el('g', { transform: 'translate(0 ' + (30 + i * 56) + ')', opacity: 0 }, tree);
        var ico = fileIcon(g, 0, 0, 'plain', null);
        text(g, 76, 38, rows[i], { fill: COL.body, size: 14 });
        fileNodes.push({ g: g, ico: ico, row: i });
        defer(function () {
          timer(400, function (t) { g.setAttribute('opacity', easeOut(t)); });
        }, 200 + i * 100);
      })(i);
    }

    // worker pool on the right
    defer(function () {
      text(stage, 750, 130, 'WORKERS', {
        fill: COL.muted, anchor: 'middle', size: 12, tracking: 4
      });
      for (var k = 0; k < 4; k++) {
        var wx = 660 + k * 60;
        el('rect', {
          x: wx, y: 150, width: 44, height: 44, rx: 8,
          fill: 'rgba(13,19,32,0.85)', stroke: COL.accent, 'stroke-width': 1
        }, stage);
        var cog = el('text', {
          x: wx + 22, y: 178,
          fill: COL.accent, 'font-size': 14, 'text-anchor': 'middle',
          'font-weight': 700
        }, stage);
        cog.textContent = 'W' + (k + 1);
      }
    }, 800);

    // sweep: replace plain icons with locked icons one by one
    defer(function () {
      for (var i = 0; i < rows.length; i++) {
        (function (i) {
          defer(function () {
            var fn = fileNodes[i];
            // clear old icon
            while (fn.g.firstChild) fn.g.removeChild(fn.g.firstChild);
            fileIcon(fn.g, 0, 0, 'locked', null);
            text(fn.g, 76, 38, rows[i], { fill: COL.body, size: 14 });
            pulse(fn.g, 30, 38, COL.success);
          }, i * 350);
        })(i);
      }
    }, 1500);

    defer(function () {
      var note = el('text', {
        x: 550, y: 460, fill: COL.text,
        'font-size': 18, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      note.textContent = 'Bounded parallelism. Atomic temp-and-rename writes.';
      timer(500, function (t) { note.setAttribute('opacity', easeOut(t)); });

      var n2 = el('text', {
        x: 550, y: 490, fill: COL.muted,
        'font-size': 14,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n2.textContent = 'Already-encrypted files skip with ErrAlreadyEncrypted.';
      timer(500, function (t) { n2.setAttribute('opacity', easeOut(t)); });
    }, 4500);
  }

  /* ---------- Scene 6: recipients ---------- */
  function scene6(stage) {
    defs(stage);
    text(stage, 550, 70, 'ADD A RECIPIENT', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    // file
    var f = el('g', { transform: 'translate(360 140)' }, stage);
    el('rect', {
      x: 0, y: 0, width: 380, height: 320, rx: 12,
      fill: 'rgba(13,19,32,0.92)', stroke: 'rgba(255,255,255,0.12)', 'stroke-width': 1
    }, f);
    text(f, 20, 30, 'secrets.yaml', { fill: COL.text, size: 14, weight: 700 });
    text(f, 20, 50, 'sops encrypted file', { fill: COL.muted, size: 11 });

    // payload box
    el('rect', {
      x: 20, y: 70, width: 340, height: 80, rx: 8,
      fill: 'rgba(249,99,2,0.10)', stroke: COL.accent, 'stroke-width': 1
    }, f);
    text(f, 190, 100, 'payload', { fill: COL.accent, anchor: 'middle', size: 12, tracking: 4, weight: 700 });
    text(f, 190, 124, '[AES-GCM ciphertext]', {
      fill: COL.muted, anchor: 'middle', size: 12,
      family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
    });

    // metadata box
    el('rect', {
      x: 20, y: 165, width: 340, height: 130, rx: 8,
      fill: 'rgba(126,169,255,0.08)', stroke: 'rgba(126,169,255,0.5)', 'stroke-width': 1
    }, f);
    text(f, 190, 188, 'metadata . wrapped data keys', {
      fill: '#7ea9ff', anchor: 'middle', size: 12, tracking: 3, weight: 700
    });

    // initial 2 wrapped keys
    var keys = [
      { id: 'alice@example.com', t: 'age1qyqsz...' },
      { id: 'ops-team',          t: 'age1tdpz...' }
    ];
    for (var i = 0; i < 2; i++) {
      (function (i) {
        var k = el('g', {
          transform: 'translate(' + (35 + i * 165) + ' 210)',
          opacity: 0
        }, f);
        chip(k, 0, 0, 150, 64, '', keys[i].id, keys[i].t);
        timer(500, function (t) { k.setAttribute('opacity', easeOut(t)); });
      })(i);
    }

    // Bob's key flies in
    defer(function () {
      var bob = el('g', {
        transform: 'translate(900 200)', opacity: 0
      }, stage);
      chip(bob, 0, 0, 150, 64, 'accent', 'bob@example.com', 'age1bob...');
      pulse(bob, 75, 32, COL.accent);
      timer(600, function (t) { bob.setAttribute('opacity', easeOut(t)); });

      // fly to slot 3 in the file
      defer(function () {
        timer(900, function (t) {
          var e = easeOut(t);
          var x = 900 + (360 - 900) * e; // target near slot 3 in file
          var y = 200 + (350 - 200) * e;
          bob.setAttribute('transform', 'translate(' + x + ' ' + y + ')');
        });
      }, 800);

      // payload pulses to show it did NOT change
      defer(function () {
        var note = el('text', {
          x: 550, y: 510,
          fill: COL.text, 'font-size': 18, 'font-weight': 700,
          'text-anchor': 'middle', opacity: 0
        }, stage);
        note.textContent = 'Only the wrapped key changes. Payload is byte-for-byte identical.';
        timer(500, function (t) { note.setAttribute('opacity', easeOut(t)); });
      }, 1900);
    }, 1100);
  }

  /* ---------- Scene 7: precommit ---------- */
  function scene7(stage) {
    defs(stage);
    text(stage, 550, 70, 'PRE-COMMIT', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 6, weight: 600
    });

    // staged files
    var staged = ['README.md', 'src/main.go', 'secrets/prod.yaml'];
    var kinds  = ['plain',     'plain',       'flagged'];
    var sg = el('g', { transform: 'translate(150 150)' }, stage);
    text(sg, 0, 0, 'git diff --cached', {
      fill: COL.muted, size: 12, weight: 700,
      family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
    });
    for (var i = 0; i < 3; i++) {
      (function (i) {
        var g = el('g', { transform: 'translate(0 ' + (30 + i * 96) + ')', opacity: 0 }, sg);
        fileIcon(g, 0, 0, kinds[i], null);
        text(g, 76, 24, staged[i], { fill: COL.body, size: 14, weight: 700 });
        text(g, 76, 44, kinds[i] === 'flagged'
          ? 'plaintext, matches .sops.yaml rule'
          : 'no rule applies', {
          fill: kinds[i] === 'flagged' ? COL.critical : COL.muted, size: 11
        });
        defer(function () {
          timer(400, function (t) { g.setAttribute('opacity', easeOut(t)); });
        }, 200 + i * 300);
      })(i);
    }

    // checker
    defer(function () {
      var ch = el('g', { transform: 'translate(680 150)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 280, height: 200, rx: 12,
        fill: 'rgba(13,19,32,0.92)',
        stroke: COL.accent, 'stroke-width': 1
      }, ch);
      text(ch, 140, 36, 'cipher precommit', {
        fill: COL.accent, anchor: 'middle', size: 16, weight: 700
      });
      text(ch, 140, 64, '.sops.yaml rules', {
        fill: COL.muted, anchor: 'middle', size: 11, tracking: 4
      });

      // rules
      var rules = [
        'path_regex: secrets/.*\\.yaml',
        'recipients: age1ops...'
      ];
      for (var k = 0; k < rules.length; k++) {
        text(ch, 20, 100 + k * 20, rules[k], {
          fill: COL.body, size: 11,
          family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
        });
      }
      timer(500, function (t) { ch.setAttribute('opacity', easeOut(t)); });
    }, 1200);

    defer(function () {
      var out = el('g', { transform: 'translate(680 380)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 280, height: 80, rx: 8,
        fill: 'rgba(240,98,98,0.10)', stroke: COL.critical, 'stroke-width': 1
      }, out);
      text(out, 140, 30, 'BLOCKED', {
        fill: COL.critical, anchor: 'middle', size: 14, weight: 700, tracking: 4
      });
      text(out, 140, 56, 'secrets/prod.yaml', {
        fill: COL.body, anchor: 'middle', size: 12,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
      });
      text(out, 140, 72, 'matches rule but is not encrypted', {
        fill: COL.muted, anchor: 'middle', size: 11
      });
      timer(500, function (t) { out.setAttribute('opacity', easeOut(t)); });
    }, 2000);
  }

  /* ---------- Scene 8: CTA ---------- */
  function scene8(stage) {
    defs(stage);

    var w = text(stage, 550, 180, 'cipher', {
      fill: COL.text, anchor: 'middle', size: 64, weight: 700, opacity: 0
    });
    timer(600, function (t) { w.setAttribute('opacity', easeOut(t)); });

    defer(function () {
      var g = el('g', { transform: 'translate(280 240)', opacity: 0 }, stage);
      code(g, 0, 0, [
        { t: 'go get github.com/dcadolph/cipher', c: COL.accent },
        { t: 'go install github.com/dcadolph/cipher/cmd/cipher@latest', c: COL.body }
      ], { w: 540 });
      timer(600, function (t) { g.setAttribute('opacity', easeOut(t)); });
    }, 500);

    defer(function () {
      var n = el('text', {
        x: 550, y: 430, fill: COL.text,
        'font-size': 22, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'cipher demo';
      timer(500, function (t) { n.setAttribute('opacity', easeOut(t)); });

      var s = el('text', {
        x: 550, y: 460, fill: COL.muted,
        'font-size': 14,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      s.textContent = 'opens this browser. Five more explainers: intro, how it works, walks, recipients, pre-commit.';
      timer(500, function (t) { s.setAttribute('opacity', easeOut(t)); });
    }, 1300);
  }

  /* ---------- the SCENES array ---------- */
  var SCENES = [
    {
      label: '1 / 8 . cipher',
      duration: 6500,
      caption:
        "<span class='accent'>cipher</span>" +
        "<br/><span class='sub'>Programmatic sops, from Go. With everything that comes after.</span>",
      paint: scene1
    },
    {
      label: '2 / 8 . the gap',
      duration: 12000,
      caption:
        "Sops has a stable <span class='accent'>decrypt</span> API." +
        "<br/><span class='sub'>Encrypting from Go is fifty lines of boilerplate. cipher absorbs it.</span>",
      paint: scene2
    },
    {
      label: '3 / 8 . four interfaces',
      duration: 13000,
      caption:
        "Four single-method interfaces with <span class='accent'>Func adapters</span>." +
        "<br/><span class='sub'>Plain functions satisfy them. http.HandlerFunc style.</span>",
      paint: scene3
    },
    {
      label: '4 / 8 . encrypt',
      duration: 11000,
      caption:
        "Encrypt is <span class='accent'>one call</span>." +
        "<br/><span class='sub'>Path drives format. KeyProvider drives recipients. Defaults handle the rest.</span>",
      paint: scene4
    },
    {
      label: '5 / 8 . walks',
      duration: 13000,
      caption:
        "Walk a tree with <span class='accent'>bounded parallelism</span>." +
        "<br/><span class='sub'>Skip signals are first-class. Writes are temp-and-rename atomic.</span>",
      paint: scene5
    },
    {
      label: '6 / 8 . recipients',
      duration: 12000,
      caption:
        "<span class='accent'>Add</span> a recipient. Payload does not move." +
        "<br/><span class='sub'>Only the wrapped data key changes. Same goes for RemoveRecipient.</span>",
      paint: scene6
    },
    {
      label: '7 / 8 . pre-commit',
      duration: 10500,
      caption:
        "<span class='accent'>Block</span> plaintext at the git door." +
        "<br/><span class='sub'>Hook walks staged blobs against .sops.yaml. Wrong file, no commit.</span>",
      paint: scene7
    },
    {
      label: '8 / 8 . go',
      duration: 9000,
      caption:
        "<span class='accent'>go get</span> . <span class='accent'>cipher demo</span> . done." +
        "<br/><span class='sub'>Five more explainers are one click away.</span>",
      paint: scene8
    }
  ];

  C.run({ scenes: SCENES });
})();
