/*
 * explainer-recipients.js
 *
 * Recipients cinematic: add and remove without re-encrypting.
 * Six scenes, ~60 s.
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

  function fileFrame(stage, x, y, w, h, title) {
    var f = el('g', { transform: 'translate(' + x + ' ' + y + ')' }, stage);
    el('rect', {
      x: 0, y: 0, width: w, height: h, rx: 14,
      fill: 'rgba(13,19,32,0.92)', stroke: 'rgba(255,255,255,0.12)', 'stroke-width': 1
    }, f);
    text(f, 20, 32, title, { fill: COL.text, size: 14, weight: 700 });
    text(f, 20, 52, 'sops-encrypted file', { fill: COL.muted, size: 11 });
    return f;
  }

  function payloadBox(parent, x, y, w) {
    var g = el('g', { transform: 'translate(' + x + ' ' + y + ')' }, parent);
    el('rect', {
      x: 0, y: 0, width: w, height: 80, rx: 10,
      fill: 'rgba(249,99,2,0.10)', stroke: COL.accent, 'stroke-width': 1
    }, g);
    text(g, w / 2, 28, 'payload', {
      fill: COL.accent, anchor: 'middle', size: 12, tracking: 4, weight: 700
    });
    text(g, w / 2, 56, '[AES-GCM ciphertext]', {
      fill: COL.muted, anchor: 'middle', size: 12,
      family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
    });
    return g;
  }

  function keyChip(parent, x, y, w, label, sub, color) {
    var g = el('g', { transform: 'translate(' + x + ' ' + y + ')', opacity: 0 }, parent);
    var fill = color ? 'rgba(249,99,2,0.14)' : 'rgba(255,255,255,0.05)';
    var stroke = color ? COL.accent : 'rgba(255,255,255,0.15)';
    el('rect', {
      x: 0, y: 0, width: w, height: 60, rx: 8,
      fill: fill, stroke: stroke, 'stroke-width': 1
    }, g);
    text(g, w / 2, 28, label, {
      fill: COL.text, anchor: 'middle', size: 13, weight: 700
    });
    text(g, w / 2, 48, sub, {
      fill: COL.muted, anchor: 'middle', size: 11,
      family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
    });
    return g;
  }

  /* Scene 1: title */
  function scene1(stage) {
    var w = text(stage, 550, 270, 'recipients', {
      fill: COL.text, anchor: 'middle', size: 76, weight: 700, opacity: 0
    });
    timer(700, function (t) { w.setAttribute('opacity', easeOut(t)); });
    defer(function () {
      var s = text(stage, 550, 330, 'add and remove without re-encrypting', {
        fill: COL.muted, anchor: 'middle', size: 18, tracking: 3, opacity: 0
      });
      timer(700, function (t) { s.setAttribute('opacity', 0.85 * easeOut(t)); });
    }, 400);
  }

  /* Scene 2: anatomy of a sops file */
  function scene2(stage) {
    text(stage, 550, 70, 'ANATOMY OF A SOPS FILE', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    var f = fileFrame(stage, 270, 110, 560, 420, 'secrets.yaml');

    // payload
    var p = payloadBox(f, 40, 90, 480);
    p.setAttribute('opacity', '0');
    timer(600, function (t) { p.setAttribute('opacity', easeOut(t)); });

    // metadata heading
    defer(function () {
      var heading = text(f, 280, 210, 'metadata . wrapped data keys', {
        fill: '#7ea9ff', anchor: 'middle', size: 12, tracking: 3, weight: 700, opacity: 0
      });
      timer(400, function (t) { heading.setAttribute('opacity', easeOut(t)); });

      var keys = [
        { l: 'alice@example.com', s: 'age1qyqsz...' },
        { l: 'ops-team',          s: 'age1tdpz...' }
      ];
      for (var i = 0; i < 2; i++) {
        (function (i) {
          var k = keyChip(f, 60 + i * 220, 230, 200, keys[i].l, keys[i].s);
          defer(function () {
            timer(500, function (t) { k.setAttribute('opacity', easeOut(t)); });
          }, 400 + i * 200);
        })(i);
      }
    }, 800);

    defer(function () {
      var n = el('text', {
        x: 550, y: 460,
        fill: COL.text, 'font-size': 16, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, f);
      n.textContent = 'Each recipient gets its own wrapped copy of the same data key.';
      timer(500, function (t) { n.setAttribute('opacity', easeOut(t)); });
    }, 1800);
  }

  /* Scene 3: AddRecipient (Bob joins) */
  function scene3(stage) {
    text(stage, 550, 70, 'ADD A RECIPIENT', {
      fill: COL.accent, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    var f = fileFrame(stage, 270, 110, 560, 420, 'secrets.yaml');
    var p = payloadBox(f, 40, 90, 480);
    text(f, 280, 210, 'metadata . wrapped data keys', {
      fill: '#7ea9ff', anchor: 'middle', size: 12, tracking: 3, weight: 700
    });
    keyChip(f, 60, 230, 200, 'alice@example.com', 'age1qyqsz...').setAttribute('opacity', '1');
    keyChip(f, 280, 230, 200, 'ops-team', 'age1tdpz...').setAttribute('opacity', '1');

    // Bob from off-stage
    defer(function () {
      var bob = el('g', {
        transform: 'translate(900 230)', opacity: 0
      }, stage);
      el('rect', {
        x: 0, y: 0, width: 200, height: 60, rx: 8,
        fill: 'rgba(249,99,2,0.18)', stroke: COL.accent, 'stroke-width': 1.5
      }, bob);
      text(bob, 100, 28, 'bob@example.com', {
        fill: COL.text, anchor: 'middle', size: 13, weight: 700
      });
      text(bob, 100, 48, 'age1bob...', {
        fill: COL.muted, anchor: 'middle', size: 11,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
      });
      pulse(bob, 100, 30, COL.accent);
      timer(500, function (t) { bob.setAttribute('opacity', easeOut(t)); });

      // animate to land below alice and ops in the file metadata
      defer(function () {
        timer(1100, function (t) {
          var e = easeOut(t);
          var x = 900 + (440 - 900) * e;
          var y = 230 + (430 - 230) * e;
          bob.setAttribute('transform', 'translate(' + x + ' ' + y + ')');
        });
      }, 700);
    }, 800);

    // payload sit-still callout
    defer(function () {
      var cl = el('g', { transform: 'translate(870 140)', opacity: 0 }, stage);
      el('path', {
        d: 'M 0 50 L -50 30',
        stroke: COL.accent, 'stroke-width': 1.5, fill: 'none',
        'stroke-dasharray': '4 4'
      }, cl);
      text(cl, 12, 30, 'payload', {
        fill: COL.accent, size: 12, weight: 700, tracking: 3
      });
      text(cl, 12, 50, 'unchanged', {
        fill: COL.body, size: 13, weight: 700
      });
      text(cl, 12, 70, 'byte for byte', {
        fill: COL.muted, size: 12
      });
      timer(600, function (t) { cl.setAttribute('opacity', easeOut(t)); });
    }, 2300);
  }

  /* Scene 4: RemoveRecipient */
  function scene4(stage) {
    text(stage, 550, 70, 'REMOVE A RECIPIENT', {
      fill: COL.critical, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    var f = fileFrame(stage, 270, 110, 560, 420, 'secrets.yaml');
    payloadBox(f, 40, 90, 480);
    text(f, 280, 210, 'metadata . wrapped data keys', {
      fill: '#7ea9ff', anchor: 'middle', size: 12, tracking: 3, weight: 700
    });

    var alice = keyChip(f, 60, 230, 200, 'alice@example.com', 'age1qyqsz...');
    alice.setAttribute('opacity', '1');
    var ops = keyChip(f, 280, 230, 200, 'ops-team', 'age1tdpz...');
    ops.setAttribute('opacity', '1');
    var bob = keyChip(f, 170, 320, 200, 'bob@example.com', 'age1bob...', true);
    bob.setAttribute('opacity', '1');

    // Bob fades out
    defer(function () {
      timer(900, function (t) {
        var e = easeOut(t);
        bob.setAttribute('opacity', 1 - e);
        // also translate Bob to the right
        bob.setAttribute('transform', 'translate(' + (170 + e * 400) + ' 320)');
      });
    }, 700);

    // payload pulse: still unchanged
    defer(function () {
      pulse(f, 280, 130, COL.accent);
    }, 1600);

    defer(function () {
      var n = el('text', {
        x: 550, y: 555, fill: COL.text,
        'font-size': 18, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'Wrapped key dropped. Payload still byte-for-byte identical.';
      timer(500, function (t) { n.setAttribute('opacity', easeOut(t)); });
    }, 1900);
  }

  /* Scene 5: rotation matters */
  function scene5(stage) {
    text(stage, 550, 70, 'BUT IF THE DATA KEY LEAKED', {
      fill: COL.warning, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    // problem callout
    var prob = el('g', { transform: 'translate(160 130)', opacity: 0 }, stage);
    el('rect', {
      x: 0, y: 0, width: 360, height: 240, rx: 12,
      fill: 'rgba(240,98,98,0.06)', stroke: COL.critical, 'stroke-width': 1
    }, prob);
    text(prob, 180, 38, 'REMOVAL ALONE', {
      fill: COL.critical, anchor: 'middle', size: 14, tracking: 6, weight: 700
    });
    text(prob, 30, 80, 'Removing a recipient drops their', { fill: COL.body, size: 14 });
    text(prob, 30, 102, 'wrapped key from the metadata.', { fill: COL.body, size: 14 });
    text(prob, 30, 138, "But the underlying data key is", { fill: COL.body, size: 14 });
    text(prob, 30, 160, "still the same. If they already", { fill: COL.body, size: 14 });
    text(prob, 30, 182, "extracted it, they still decrypt.", { fill: COL.body, size: 14 });
    timer(500, function (t) { prob.setAttribute('opacity', easeOut(t)); });

    // solution callout
    defer(function () {
      var sol = el('g', { transform: 'translate(580 130)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 360, height: 240, rx: 12,
        fill: 'rgba(90,201,148,0.06)', stroke: COL.success, 'stroke-width': 1
      }, sol);
      text(sol, 180, 38, 'ROTATE TOO', {
        fill: COL.success, anchor: 'middle', size: 14, tracking: 6, weight: 700
      });
      text(sol, 30, 80, 'cipher.Rotate generates a new', { fill: COL.body, size: 14 });
      text(sol, 30, 102, 'data key. Old key no longer', { fill: COL.body, size: 14 });
      text(sol, 30, 124, 'matches the file.', { fill: COL.body, size: 14 });
      text(sol, 30, 160, 'cipher rotate secrets.yaml', {
        fill: COL.success,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 14, weight: 700
      });
      text(sol, 30, 196, '. or RotateWalk for a whole tree.', { fill: COL.muted, size: 12 });
      timer(500, function (t) { sol.setAttribute('opacity', easeOut(t)); });
    }, 700);

    defer(function () {
      var n = el('text', {
        x: 550, y: 420, fill: COL.text,
        'font-size': 18, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'Removal is fast. Rotation is the durable answer.';
      timer(500, function (t) { n.setAttribute('opacity', easeOut(t)); });
    }, 1500);
  }

  /* Scene 6: CTA */
  function scene6(stage) {
    var w = text(stage, 550, 170, 'recipients', {
      fill: COL.text, anchor: 'middle', size: 52, weight: 700, opacity: 0
    });
    timer(500, function (t) { w.setAttribute('opacity', easeOut(t)); });

    defer(function () {
      var g = el('g', { transform: 'translate(190 230)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 720, height: 64, rx: 10,
        fill: 'rgba(10,12,18,0.92)',
        stroke: 'rgba(255,255,255,0.08)', 'stroke-width': 1
      }, g);
      text(g, 18, 38, '$ cipher add-recipient secrets.yaml --age age1bob...', {
        fill: COL.body,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 14
      });
      timer(500, function (t) { g.setAttribute('opacity', easeOut(t)); });

      var g2 = el('g', { transform: 'translate(190 310)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 720, height: 64, rx: 10,
        fill: 'rgba(10,12,18,0.92)',
        stroke: 'rgba(255,255,255,0.08)', 'stroke-width': 1
      }, g2);
      text(g2, 18, 38, '$ cipher remove-recipient secrets.yaml age1bob...', {
        fill: COL.body,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 14
      });
      defer(function () {
        timer(500, function (t) { g2.setAttribute('opacity', easeOut(t)); });
      }, 200);

      var g3 = el('g', { transform: 'translate(190 390)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 720, height: 64, rx: 10,
        fill: 'rgba(90,201,148,0.08)',
        stroke: COL.success, 'stroke-width': 1
      }, g3);
      text(g3, 18, 38, '$ cipher rotate secrets.yaml   # after a removal that mattered', {
        fill: COL.success,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 14, weight: 700
      });
      defer(function () {
        timer(500, function (t) { g3.setAttribute('opacity', easeOut(t)); });
      }, 500);
    }, 400);
  }

  var SCENES = [
    {
      label: '1 / 6 . recipients',
      duration: 5500,
      caption:
        "Add and remove recipients <span class='accent'>without</span> re-encrypting." +
        "<br/><span class='sub'>Metadata-only edits. Payload is byte-for-byte identical.</span>",
      paint: scene1
    },
    {
      label: '2 / 6 . anatomy',
      duration: 11500,
      caption:
        "A sops file holds <span class='accent'>two parts</span>." +
        "<br/><span class='sub'>The payload, and one wrapped data key per recipient.</span>",
      paint: scene2
    },
    {
      label: '3 / 6 . add',
      duration: 11000,
      caption:
        "<span class='accent'>AddRecipient</span> wraps the data key for one more identity." +
        "<br/><span class='sub'>Caller must already hold one existing identity. Payload does not move.</span>",
      paint: scene3
    },
    {
      label: '4 / 6 . remove',
      duration: 10500,
      caption:
        "<span class='accent'>RemoveRecipient</span> drops a wrapped key by identifier." +
        "<br/><span class='sub'>By recipient string, ARN, URI. Whatever .ToString() returns.</span>",
      paint: scene4
    },
    {
      label: '5 / 6 . rotate',
      duration: 11000,
      caption:
        "Removal is fast. <span class='accent'>Rotation</span> is the durable answer." +
        "<br/><span class='sub'>If the data key leaked, only a new one stops the old recipient.</span>",
      paint: scene5
    },
    {
      label: '6 / 6 . run it',
      duration: 9000,
      caption:
        "<span class='accent'>cipher add-recipient</span> . <span class='accent'>remove-recipient</span> . <span class='accent'>rotate</span>." +
        "<br/><span class='sub'>From Go: cipher.AddRecipient, RemoveRecipient, Rotate.</span>",
      paint: scene6
    }
  ];

  C.run({ scenes: SCENES });
})();
