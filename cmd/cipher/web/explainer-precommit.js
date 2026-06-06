/*
 * explainer-precommit.js
 *
 * Pre-commit cinematic: block plaintext at the git door.
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

  function fileIcon(parent, x, y, kind) {
    var g = el('g', { transform: 'translate(' + x + ' ' + y + ')' }, parent);
    var color =
      kind === 'locked' ? COL.success :
      kind === 'flagged' ? COL.critical :
      kind === 'plain' ? COL.body :
      COL.muted;
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
    } else if (kind === 'flagged') {
      text(g, 21, 38, '!', {
        fill: COL.critical, anchor: 'middle', size: 22, weight: 700
      });
    }
    return g;
  }

  /* Scene 1: title */
  function scene1(stage) {
    var w = text(stage, 550, 250, 'pre-commit', {
      fill: COL.text, anchor: 'middle', size: 72, weight: 700, opacity: 0
    });
    timer(700, function (t) { w.setAttribute('opacity', easeOut(t)); });
    defer(function () {
      var s = text(stage, 550, 320, 'block plaintext at the git door', {
        fill: COL.muted, anchor: 'middle', size: 18, tracking: 4, opacity: 0
      });
      timer(700, function (t) { s.setAttribute('opacity', 0.85 * easeOut(t)); });
    }, 400);

    defer(function () {
      var note = text(stage, 550, 400, 'one shell line, one less production incident', {
        fill: COL.body, anchor: 'middle', size: 14, opacity: 0
      });
      timer(700, function (t) { note.setAttribute('opacity', 0.85 * easeOut(t)); });
    }, 1000);
  }

  /* Scene 2: setup */
  function scene2(stage) {
    text(stage, 550, 70, 'THE SETUP', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    // .sops.yaml
    var cfg = el('g', { transform: 'translate(110 130)', opacity: 0 }, stage);
    el('rect', {
      x: 0, y: 0, width: 380, height: 200, rx: 12,
      fill: 'rgba(13,19,32,0.92)',
      stroke: 'rgba(255,255,255,0.12)', 'stroke-width': 1
    }, cfg);
    text(cfg, 20, 30, '.sops.yaml', {
      fill: COL.accent, size: 16, weight: 700,
      family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
    });
    var lines = [
      'creation_rules:',
      '  - path_regex: secrets/.*\\.yaml',
      '    key_groups:',
      '      - age:',
      '          - age1ops...'
    ];
    for (var i = 0; i < lines.length; i++) {
      text(cfg, 20, 60 + i * 22, lines[i], {
        fill: COL.body, size: 12,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
      });
    }
    timer(500, function (t) { cfg.setAttribute('opacity', easeOut(t)); });

    // .git/hooks/pre-commit
    defer(function () {
      var hk = el('g', { transform: 'translate(580 130)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 380, height: 200, rx: 12,
        fill: 'rgba(13,19,32,0.92)',
        stroke: 'rgba(255,255,255,0.12)', 'stroke-width': 1
      }, hk);
      text(hk, 20, 30, '.git/hooks/pre-commit', {
        fill: COL.accent, size: 16, weight: 700,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
      });
      text(hk, 20, 60, '#!/usr/bin/env bash', {
        fill: COL.muted, size: 13,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
      });
      text(hk, 20, 86, 'exec cipher precommit', {
        fill: COL.text, size: 15, weight: 700,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
      });
      text(hk, 20, 130, 'chmod +x to install.', {
        fill: COL.muted, size: 12
      });
      text(hk, 20, 152, 'Two lines is the whole hook.', {
        fill: COL.muted, size: 12
      });
      timer(500, function (t) { hk.setAttribute('opacity', easeOut(t)); });
    }, 800);

    defer(function () {
      var n = el('text', {
        x: 550, y: 480, fill: COL.text,
        'font-size': 18, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'Same .sops.yaml the sops CLI already uses.';
      timer(500, function (t) { n.setAttribute('opacity', easeOut(t)); });
    }, 1800);
  }

  /* Scene 3: staged blob check */
  function scene3(stage) {
    text(stage, 550, 70, 'WHAT IT INSPECTS', {
      fill: COL.muted, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    // git staging area
    var ga = el('g', { transform: 'translate(110 140)' }, stage);
    text(ga, 0, 0, 'git diff --cached', {
      fill: COL.muted, size: 14, weight: 700,
      family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
    });

    var files = [
      { name: 'README.md',         kind: 'plain',   note: 'no rule applies' },
      { name: 'src/main.go',       kind: 'plain',   note: 'no rule applies' },
      { name: 'secrets/db.yaml',   kind: 'locked',  note: 'matches rule, already encrypted' },
      { name: 'secrets/tls.yaml',  kind: 'plain',   note: 'matches rule but is plaintext' }
    ];
    var rowG = [];
    for (var i = 0; i < files.length; i++) {
      (function (i) {
        var g = el('g', { transform: 'translate(0 ' + (40 + i * 70) + ')', opacity: 0 }, ga);
        fileIcon(g, 0, 0, files[i].kind);
        text(g, 60, 22, files[i].name, {
          fill: COL.body, size: 14,
          family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
        });
        text(g, 60, 44, files[i].note, {
          fill: COL.muted, size: 11
        });
        rowG.push(g);
        defer(function () {
          timer(400, function (t) { g.setAttribute('opacity', easeOut(t)); });
        }, 200 + i * 220);
      })(i);
    }

    // checker on the right
    defer(function () {
      var ch = el('g', { transform: 'translate(620 200)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 320, height: 180, rx: 12,
        fill: 'rgba(13,19,32,0.92)',
        stroke: COL.accent, 'stroke-width': 1
      }, ch);
      text(ch, 160, 36, 'precommit.Checker', {
        fill: COL.accent, anchor: 'middle', size: 16, weight: 700,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace'
      });
      text(ch, 30, 70, '1. List staged blobs.', { fill: COL.body, size: 13 });
      text(ch, 30, 94, '2. Match .sops.yaml rules.', { fill: COL.body, size: 13 });
      text(ch, 30, 118, '3. Verify each blob is', { fill: COL.body, size: 13 });
      text(ch, 30, 138, '   sops-encrypted.', { fill: COL.body, size: 13 });
      text(ch, 30, 168, 'No working-tree shortcuts.', { fill: COL.muted, size: 11 });
      timer(500, function (t) { ch.setAttribute('opacity', easeOut(t)); });
    }, 1300);

    defer(function () {
      var n = el('text', {
        x: 550, y: 550, fill: COL.text,
        'font-size': 16, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'The hook inspects staged blobs. Working-tree edits do not affect the verdict.';
      timer(500, function (t) { n.setAttribute('opacity', easeOut(t)); });
    }, 2300);
  }

  /* Scene 4: the catch */
  function scene4(stage) {
    text(stage, 550, 70, 'THE CATCH', {
      fill: COL.critical, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    // terminal showing the failure output
    var t1 = el('g', { transform: 'translate(150 130)', opacity: 0 }, stage);
    el('rect', {
      x: 0, y: 0, width: 800, height: 260, rx: 12,
      fill: 'rgba(10,12,18,0.95)',
      stroke: 'rgba(255,255,255,0.12)', 'stroke-width': 1
    }, t1);
    el('circle', { cx: 20, cy: 20, r: 5, fill: '#f06262' }, t1);
    el('circle', { cx: 36, cy: 20, r: 5, fill: '#f9b342' }, t1);
    el('circle', { cx: 52, cy: 20, r: 5, fill: '#5ac994' }, t1);

    var lines = [
      { t: '$ git commit -m "add secrets"', c: COL.body, mono: true },
      { t: 'cipher precommit . scanning 4 staged files', c: COL.muted, mono: true },
      { t: '', c: COL.body },
      { t: 'BLOCKED: secrets/tls.yaml: matches rule but is not sops-encrypted', c: COL.critical, mono: true },
      { t: '', c: COL.body },
      { t: 'commit aborted (exit 1)', c: COL.critical, mono: true, weight: 700 }
    ];
    for (var i = 0; i < lines.length; i++) {
      (function (i) {
        var l = lines[i];
        defer(function () {
          var tt = text(t1, 24, 56 + i * 28, l.t, {
            fill: l.c,
            family: l.mono ? 'ui-monospace, SFMono-Regular, Menlo, monospace' : null,
            size: 14, weight: l.weight || 400
          });
          if (i === 3) pulse(t1, 24, 50 + i * 28, COL.critical, { dur: 1000, r0: 4, r1: 18 });
        }, 200 + i * 280);
      })(i);
    }
    timer(500, function (t) { t1.setAttribute('opacity', easeOut(t)); });

    defer(function () {
      var n = el('text', {
        x: 550, y: 460, fill: COL.text,
        'font-size': 18, 'font-weight': 700,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'No plaintext secret reaches the repo.';
      timer(500, function (t) { n.setAttribute('opacity', easeOut(t)); });

      var n2 = el('text', {
        x: 550, y: 488, fill: COL.muted,
        'font-size': 14,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n2.textContent = 'The developer fixes locally and re-commits.';
      timer(500, function (t) { n2.setAttribute('opacity', easeOut(t)); });
    }, 2800);
  }

  /* Scene 5: the save */
  function scene5(stage) {
    text(stage, 550, 70, 'THE SAVE', {
      fill: COL.success, anchor: 'middle', size: 14, tracking: 5, weight: 600
    });

    var t1 = el('g', { transform: 'translate(150 130)', opacity: 0 }, stage);
    el('rect', {
      x: 0, y: 0, width: 800, height: 320, rx: 12,
      fill: 'rgba(10,12,18,0.95)',
      stroke: 'rgba(255,255,255,0.12)', 'stroke-width': 1
    }, t1);
    el('circle', { cx: 20, cy: 20, r: 5, fill: '#f06262' }, t1);
    el('circle', { cx: 36, cy: 20, r: 5, fill: '#f9b342' }, t1);
    el('circle', { cx: 52, cy: 20, r: 5, fill: '#5ac994' }, t1);

    var lines = [
      { t: '$ cipher encrypt -i secrets/tls.yaml --config .', c: COL.accent, weight: 700 },
      { t: '$ git add secrets/tls.yaml', c: COL.body },
      { t: '$ git commit -m "add secrets"', c: COL.body },
      { t: 'cipher precommit . scanning 4 staged files', c: COL.muted },
      { t: '. all sops-encrypted (or do not match any rule)', c: COL.success, weight: 700 },
      { t: '[main 9d3f2a1] add secrets', c: COL.body },
      { t: ' 4 files changed, 12 insertions(+)', c: COL.muted }
    ];
    for (var i = 0; i < lines.length; i++) {
      (function (i) {
        var l = lines[i];
        defer(function () {
          text(t1, 24, 56 + i * 32, l.t, {
            fill: l.c,
            family: 'ui-monospace, SFMono-Regular, Menlo, monospace',
            size: 14,
            weight: l.weight || 400
          });
        }, 200 + i * 280);
      })(i);
    }
    timer(500, function (t) { t1.setAttribute('opacity', easeOut(t)); });
  }

  /* Scene 6: CTA */
  function scene6(stage) {
    var w = text(stage, 550, 170, 'pre-commit', {
      fill: COL.text, anchor: 'middle', size: 52, weight: 700, opacity: 0
    });
    timer(500, function (t) { w.setAttribute('opacity', easeOut(t)); });

    defer(function () {
      var g = el('g', { transform: 'translate(220 240)', opacity: 0 }, stage);
      el('rect', {
        x: 0, y: 0, width: 660, height: 130, rx: 12,
        fill: 'rgba(10,12,18,0.95)',
        stroke: 'rgba(255,255,255,0.08)', 'stroke-width': 1
      }, g);
      text(g, 18, 32, '$ cat .git/hooks/pre-commit', {
        fill: COL.muted,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 14
      });
      text(g, 18, 60, '#!/usr/bin/env bash', {
        fill: COL.muted,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 14
      });
      text(g, 18, 84, 'exec cipher precommit', {
        fill: COL.accent,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 16, weight: 700
      });
      text(g, 18, 116, '$ chmod +x .git/hooks/pre-commit', {
        fill: COL.body,
        family: 'ui-monospace, SFMono-Regular, Menlo, monospace', size: 14
      });
      timer(600, function (t) { g.setAttribute('opacity', easeOut(t)); });
    }, 400);

    defer(function () {
      var n = el('text', {
        x: 550, y: 430, fill: COL.muted,
        'font-size': 14,
        'text-anchor': 'middle', opacity: 0
      }, stage);
      n.textContent = 'Works with the pre-commit framework too. See README for the yaml block.';
      timer(500, function (t) { n.setAttribute('opacity', 0.85 * easeOut(t)); });
    }, 1100);
  }

  var SCENES = [
    {
      label: '1 / 6 . pre-commit',
      duration: 6500,
      caption:
        "Block plaintext secrets <span class='accent'>at the git door</span>." +
        "<br/><span class='sub'>One shell line. One less production incident.</span>",
      paint: scene1
    },
    {
      label: '2 / 6 . setup',
      duration: 11000,
      caption:
        "Two pieces: <span class='accent'>.sops.yaml</span> and a tiny hook." +
        "<br/><span class='sub'>Same .sops.yaml the sops CLI already uses.</span>",
      paint: scene2
    },
    {
      label: '3 / 6 . inspect',
      duration: 11500,
      caption:
        "The hook inspects <span class='accent'>staged blobs</span>." +
        "<br/><span class='sub'>Not the working tree. The blob is what would land in the commit.</span>",
      paint: scene3
    },
    {
      label: '4 / 6 . catch',
      duration: 11500,
      caption:
        "A file matches a rule but is <span class='accent'>plaintext</span>." +
        "<br/><span class='sub'>Exit 1. The commit never happens.</span>",
      paint: scene4
    },
    {
      label: '5 / 6 . save',
      duration: 10500,
      caption:
        "Developer encrypts. <span class='accent'>Re-commits.</span> Clean." +
        "<br/><span class='sub'>cipher encrypt -i fixes the file in place using .sops.yaml.</span>",
      paint: scene5
    },
    {
      label: '6 / 6 . install',
      duration: 8000,
      caption:
        "Two lines in <span class='accent'>.git/hooks/pre-commit</span>." +
        "<br/><span class='sub'>chmod +x and you are done.</span>",
      paint: scene6
    }
  ];

  C.run({ scenes: SCENES });
})();
