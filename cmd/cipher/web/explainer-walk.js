/*
 * explainer-walk.js
 *
 * Walk cinematic: encrypt a tree in parallel.
 * Six scenes, total runtime ~60 s.
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

  function fileIcon(parent, x, y, kind) {
    var g = el('g', { transform: 'translate(' + x + ' ' + y + ')' }, parent);
    var color =
      kind === 'locked' ? COL.success :
      kind === 'reject' ? COL.muted :
      kind === 'inflight' ? COL.accent :
      COL.body;
    el('path', {
      d: 'M 0 0 L 30 0 L 42 12 L 42 56 L 0 56 Z',
      fill: 'rgba(13,19,32,0.85)',
      stroke: color, 'stroke-width': 1.5
    }, g);
    el('path', {
      d: 'M 30 0 L 30 12 L 42 12',
      fill: 'none', stroke: color, 'stroke-width': 1.5
    }, g);
    if (kind === 'locked') {
      el('rect', { x: 14, y: 28, width: 14, height: 12, rx: 2, fill: COL.success }, g);
      el('path', {
        d: 'M 16 28 L 16 24 a 5 5 0 0 1 10 0 L 26 28',
        fill: 'none', stroke: COL.success, 'stroke-width': 1.5
      }, g);
    } else if (kind === 'inflight') {
      el('circle', { cx: 21, cy: 32, r: 6, fill: 'none', stroke: COL.accent, 'stroke-width': 2 }, g);
      el('circle', { cx: 21, cy: 32, r: 2, fill: COL.accent }, g);
    } else if (kind === 'reject') {
      text(g, 21, 38, 'x', {
        fill: COL.muted, anchor: 'middle', size: 20, weight: 700
      });
    }
    return g;
  }

  /* Scene 1: title */
  function scene1(stage) {
    var w = text(stage, 550, 270, 'walk', {
      fill: COL.text, anchor: 'middle', size: 88, weight: 700, opacity: 0
    });
    timer(700, function (t) { w.setAttribute('opacity', easeOut(t)); });
    defer(function () {
      var s = text(stage, 550, 330, 'encrypt a tree, in parallel', {
        fill: COL.muted, anchor: 'middle', size: 18, tracking: 4, opacity: 0
      });
      timer(700, function (t) { s.setAttribute('opacity', 0.85 * easeOut(t)); });
    }, 400);

    // little decoration: 8 file icons fading in around the title
    defer(function () {
      for (var i = 0; i < 8; i++) {
        (function (i) {
          var angle = (i / 8) * Math.PI * 2;
          var x = 550 + Math.cos(angle) * 280;
          var y = 290 + Math.sin(angle) * 130;
          var g = fileIcon(stage, x - 21, y - 28, 'plain');
          g.setAttribute('opacity', '0');
          defer(function () {
            timer(500, function (t) { g.setAttribute('opacity', easeOut(t) * 0.5); });
          }, i * 60);
        })(i);
      }
    }, 800);
  }

  /* Scene 2: matchers */
  function scene2(stage) {
    text(stage, 550, 70, 'MATCHERS SELECT FILES', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    var files = [
      { name: 'db.yaml',     match: true },
      { name: 'tls.yaml',    match: true },
      { name: 'README.md',   match: false },
      { name: 'kv.json',     match: true },
      { name: 'main.go',     match: false },
      { name: '.gitignore',  match: false },
      { name: 'sso.yml',     match: true },
      { name: 'redis.ini',   match: false }
    ];

    var col1 = el('g', { transform: 'translate(170 130)' }, stage);
    for (var i = 0; i < files.length; i++) {
      (function (i) {
        var g = el('g', { transform: 'translate(0 ' + (i * 46) + ')', opacity: 0 }, col1);
        fileIcon(g, 0, 0, files[i].match ? 'plain' : 'reject');
        text(g, 60, 36, files[i].name, {
          fill: files[i].match ? COL.body : COL.muted, size: 14,
          family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
        });
        defer(function () {
          timer(300, function (t) { g.setAttribute('opacity', easeOut(t)); });
        }, 100 + i * 90);
      })(i);
    }

    // matcher chip
    defer(function () {
      var m = el('g', { transform: 'translate(640 200)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 320, height: 70, rx: 10,
        fill: 'rgba(249,99,2,0.12)', stroke: COL.accent, 'stroke-width': 1
      }, m);
      text(m, 160, 30, 'MatchExt("yaml", "yml", "json")', {
        fill: COL.text, anchor: 'middle', size: 14, weight: 700,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
      });
      text(m, 160, 54, 'case-insensitive, leading dot optional', {
        fill: COL.muted, anchor: 'middle', size: 11
      });
      timer(500, function (t) { m.setAttribute('opacity', easeOut(t)); });
    }, 1000);

    defer(function () {
      var n = el('text', {
        x: 550, y: 530, fill: COL.text,
        'font-size': 18, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'Four matched. The other four never see the encoder.';
      timer(500, function (t) { n.setAttribute('opacity', easeOut(t)); });
    }, 1800);
  }

  /* Scene 3: bounded parallelism */
  function scene3(stage) {
    text(stage, 550, 70, 'BOUNDED PARALLELISM', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    // semaphore visualization
    var sg = el('g', { transform: 'translate(380 130)' }, stage);
    text(sg, 170, 0, 'semaphore (capacity 4)', {
      fill: COL.muted, anchor: 'middle', size: 12, tracking: 3
    });
    for (var i = 0; i < 4; i++) {
      var x = i * 80;
      el('rect', {
        x: x, y: 20, width: 70, height: 70, rx: 10,
        fill: 'rgba(13,19,32,0.85)', stroke: 'rgba(255,255,255,0.12)', 'stroke-width': 1
      }, sg);
      text(sg, x + 35, 64, 'idle', {
        fill: COL.muted, anchor: 'middle', size: 11
      });
    }

    // workers fill in
    var jobs = ['db.yaml', 'tls.yaml', 'kv.json', 'sso.yml', 'auth.yaml', 'gh.json'];
    var slots = [
      { jobIdx: -1, label: null, gIdx: -1 },
      { jobIdx: -1, label: null, gIdx: -1 },
      { jobIdx: -1, label: null, gIdx: -1 },
      { jobIdx: -1, label: null, gIdx: -1 }
    ];

    function paintSlot(slotI, jobI) {
      var slotG = sg.children[1 + slotI * 2]; // rough index
      var slotText = sg.children[2 + slotI * 2];
      slotText.textContent = jobs[jobI] || 'idle';
      slotText.setAttribute('fill', jobs[jobI] ? COL.accent : COL.muted);
      pulse(sg, slotI * 80 + 35, 55, COL.accent);
    }

    // We can't easily target children by index reliably in the existing
    // SVG. Build the slots with explicit groups instead so we can find
    // them later. Recreate:
    while (sg.firstChild) sg.removeChild(sg.firstChild);
    text(sg, 170, 0, 'semaphore (capacity 4)', {
      fill: COL.muted, anchor: 'middle', size: 12, tracking: 3
    });
    var slotGs = [];
    for (var k = 0; k < 4; k++) {
      var x2 = k * 80;
      var sgs = el('g', { transform: 'translate(' + x2 + ' 20)' }, sg);
      el('rect', {
        x: 0, y: 0, width: 70, height: 70, rx: 10,
        fill: 'rgba(13,19,32,0.85)', stroke: 'rgba(255,255,255,0.12)', 'stroke-width': 1
      }, sgs);
      var lbl = el('text', {
        x: 35, y: 44,
        fill: COL.muted, 'font-size': 11, 'text-anchor': 'middle',
        'font-family': 'ui-monospace, SFMono-Regular, Menlo, monospace'
      }, sgs);
      lbl.textContent = 'idle';
      slotGs.push({ g: sgs, label: lbl });
    }

    // schedule jobs over time
    var slotsBusy = [false, false, false, false];
    function assign(jobI, slotI, after, dur) {
      defer(function () {
        slotsBusy[slotI] = true;
        slotGs[slotI].label.textContent = jobs[jobI];
        slotGs[slotI].label.setAttribute('fill', COL.accent);
        pulse(slotGs[slotI].g, 35, 35, COL.accent);
        defer(function () {
          slotsBusy[slotI] = false;
          slotGs[slotI].label.textContent = 'done';
          slotGs[slotI].label.setAttribute('fill', COL.success);
          defer(function () {
            slotGs[slotI].label.textContent = 'idle';
            slotGs[slotI].label.setAttribute('fill', COL.muted);
          }, 400);
        }, dur);
      }, after);
    }
    assign(0, 0, 600, 1500);
    assign(1, 1, 700, 1700);
    assign(2, 2, 800, 1600);
    assign(3, 3, 900, 1500);
    assign(4, 0, 2400, 1500);
    assign(5, 1, 2600, 1500);

    defer(function () {
      var n = el('text', {
        x: 550, y: 350, fill: COL.text,
        'font-size': 18, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'At most four files in flight. Configurable via WalkOptions.';
      timer(500, function (t) { n.setAttribute('opacity', easeOut(t)); });
    }, 1400);
  }

  /* Scene 4: atomic write */
  function scene4(stage) {
    text(stage, 550, 70, 'ATOMIC WRITES', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    // step 1: write to temp file
    var step1 = el('g', { transform: 'translate(140 150)', opacity: 0 }, stage);
    text(step1, 0, 0, '1', { fill: COL.accent, size: 20, weight: 700 });
    el('rect', {
      x: 30, y: -18, width: 380, height: 60, rx: 10,
      fill: 'rgba(249,99,2,0.10)', stroke: COL.accent, 'stroke-width': 1
    }, step1);
    text(step1, 50, 12, 'write ciphertext to', {
      fill: COL.body, size: 13
    });
    text(step1, 200, 12, 'secrets.yaml.tmp123', {
      fill: COL.accent, size: 13, weight: 700,
      family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
    });
    timer(500, function (t) { step1.setAttribute('opacity', easeOut(t)); });

    // step 2: fsync
    defer(function () {
      var step2 = el('g', { transform: 'translate(140 240)', opacity: 0 }, stage);
      text(step2, 0, 0, '2', { fill: COL.accent, size: 20, weight: 700 });
      el('rect', {
        x: 30, y: -18, width: 380, height: 60, rx: 10,
        fill: 'rgba(249,99,2,0.10)', stroke: COL.accent, 'stroke-width': 1
      }, step2);
      text(step2, 50, 12, 'fsync the temp file', {
        fill: COL.body, size: 13
      });
      timer(500, function (t) { step2.setAttribute('opacity', easeOut(t)); });
    }, 800);

    // step 3: rename
    defer(function () {
      var step3 = el('g', { transform: 'translate(140 330)', opacity: 0 }, stage);
      text(step3, 0, 0, '3', { fill: COL.accent, size: 20, weight: 700 });
      el('rect', {
        x: 30, y: -18, width: 380, height: 60, rx: 10,
        fill: 'rgba(249,99,2,0.10)', stroke: COL.accent, 'stroke-width': 1
      }, step3);
      text(step3, 50, 12, 'rename(tmp, secrets.yaml)', {
        fill: COL.body, size: 13,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
      });
      pulse(step3, 220, 12, COL.success);
      timer(500, function (t) { step3.setAttribute('opacity', easeOut(t)); });
    }, 1600);

    // result
    defer(function () {
      var r = el('g', { transform: 'translate(620 200)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 320, height: 160, rx: 12,
        fill: 'rgba(90,201,148,0.08)', stroke: COL.success, 'stroke-width': 1
      }, r);
      text(r, 160, 36, 'GUARANTEE', {
        fill: COL.success, anchor: 'middle', size: 14, tracking: 6, weight: 700
      });
      text(r, 160, 76, 'A failed write never leaves', {
        fill: COL.body, anchor: 'middle', size: 14
      });
      text(r, 160, 100, 'a half-encrypted secret on disk.', {
        fill: COL.body, anchor: 'middle', size: 14
      });
      text(r, 160, 134, 'rename(2) is atomic on POSIX.', {
        fill: COL.muted, anchor: 'middle', size: 12, tracking: 2
      });
      timer(600, function (t) { r.setAttribute('opacity', easeOut(t)); });
    }, 2400);
  }

  /* Scene 5: skip signals */
  function scene5(stage) {
    text(stage, 550, 70, 'SKIP SIGNALS', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    var rows = [
      { name: 'db.yaml',     kind: 'plain',    note: 'encrypt -> OK' },
      { name: 'tls.yaml',    kind: 'locked',   note: 'ErrAlreadyEncrypted -> OnSkip' },
      { name: 'kv.json',     kind: 'plain',    note: 'encrypt -> OK' },
      { name: 'sso.yml',     kind: 'locked',   note: 'ErrAlreadyEncrypted -> OnSkip' },
      { name: 'auth.yaml',   kind: 'plain',    note: 'encrypt -> OK' }
    ];

    for (var i = 0; i < rows.length; i++) {
      (function (i) {
        var g = el('g', {
          transform: 'translate(280 ' + (130 + i * 70) + ')',
          opacity: 0
        }, stage);
        var ico = el('g', {}, g);
        if (rows[i].kind === 'locked') {
          // already-encrypted lock icon
          el('rect', { x: 0, y: -18, width: 42, height: 56, rx: 8,
            fill: 'rgba(90,201,148,0.1)', stroke: COL.success, 'stroke-width': 1 }, ico);
          el('rect', { x: 14, y: 4, width: 14, height: 12, rx: 2, fill: COL.success }, ico);
          el('path', { d: 'M 16 4 L 16 0 a 5 5 0 0 1 10 0 L 26 4',
            fill: 'none', stroke: COL.success, 'stroke-width': 1.5 }, ico);
        } else {
          el('rect', { x: 0, y: -18, width: 42, height: 56, rx: 8,
            fill: 'rgba(255,255,255,0.05)', stroke: COL.body, 'stroke-width': 1 }, ico);
        }
        text(g, 60, 10, rows[i].name, {
          fill: COL.body, size: 14, weight: 700,
          family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
        });
        text(g, 240, 10, rows[i].note, {
          fill: rows[i].kind === 'locked' ? COL.warning : COL.success,
          size: 13
        });
        defer(function () {
          timer(400, function (t) { g.setAttribute('opacity', easeOut(t)); });
        }, 200 + i * 220);
      })(i);
    }

    defer(function () {
      var n = el('text', {
        x: 550, y: 510, fill: COL.text,
        'font-size': 18, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'Skips are first-class. They are not failures.';
      timer(500, function (t) { n.setAttribute('opacity', easeOut(t)); });

      var n2 = el('text', {
        x: 550, y: 540, fill: COL.muted,
        'font-size': 14,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n2.textContent = 'The walk continues. OnSkip gets the reason. OnFile gets the count.';
      timer(500, function (t) { n2.setAttribute('opacity', easeOut(t)); });
    }, 1500);
  }

  /* Scene 6: CTA */
  function scene6(stage) {
    var w = text(stage, 550, 180, 'walk', {
      fill: COL.text, anchor: 'middle', size: 64, weight: 700, opacity: 0
    });
    timer(500, function (t) { w.setAttribute('opacity', easeOut(t)); });

    defer(function () {
      var g = el('g', { transform: 'translate(220 240)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 660, height: 64, rx: 10,
        fill: 'rgba(10,12,18,0.92)',
        stroke: 'rgba(255,255,255,0.08)', 'stroke-width': 1
      }, g);
      text(g, 18, 38, '$ cipher walk encrypt ./secrets --ext yaml,yml,json --parallel 8', {
        fill: COL.body,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 14
      });
      timer(500, function (t) { g.setAttribute('opacity', easeOut(t)); });
    }, 400);

    defer(function () {
      var n = el('text', {
        x: 550, y: 380, fill: COL.muted,
        'font-size': 14,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'From Go: cipher.EncodeWalkWith(...). Same options, same guarantees.';
      timer(500, function (t) { n.setAttribute('opacity', 0.85 * easeOut(t)); });
    }, 1100);
  }

  var SCENES = [
    {
      label: '1 / 6 . walk',
      duration: 5500,
      caption:
        "Walk a tree, in parallel." +
        "<br/><span class='sub'>Skip signals are first-class. Writes are temp-and-rename atomic.</span>",
      paint: scene1
    },
    {
      label: '2 / 6 . matchers',
      duration: 10500,
      caption:
        "Matchers <span class='accent'>select</span> files before they reach the encoder." +
        "<br/><span class='sub'>MatchExt, MatchGlob, MatchRegex. Compose with MatchAnyOf and MatchNot.</span>",
      paint: scene2
    },
    {
      label: '3 / 6 . parallelism',
      duration: 10500,
      caption:
        "A semaphore caps in-flight work." +
        "<br/><span class='sub'>WalkOptions.Parallelism = N. Zero or one runs sequentially.</span>",
      paint: scene3
    },
    {
      label: '4 / 6 . atomic',
      duration: 11500,
      caption:
        "Write to a temp file. <span class='accent'>Then rename.</span>" +
        "<br/><span class='sub'>A failed write never leaves a half-encrypted secret on disk.</span>",
      paint: scene4
    },
    {
      label: '5 / 6 . skips',
      duration: 11000,
      caption:
        "Already-encrypted files <span class='accent'>skip</span>, not fail." +
        "<br/><span class='sub'>OnSkip fires with the sentinel. OnFile fires with the byte count.</span>",
      paint: scene5
    },
    {
      label: '6 / 6 . run it',
      duration: 8000,
      caption:
        "<span class='accent'>cipher walk encrypt</span> ./secrets --parallel 8" +
        "<br/><span class='sub'>The CLI and the Go API share the same defaults.</span>",
      paint: scene6
    }
  ];

  C.run({ scenes: SCENES });
})();
