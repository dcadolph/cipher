Output assets/demo.gif

Set Shell zsh
Set Theme "iTerm2 Default"
Set FontFamily "Menlo"
Set FontSize 18
Set Width 1100
Set Height 640
Set Padding 28
Set TypingSpeed 75ms

Hide
Type@1ms "cd /tmp && rm -rf secrets && mkdir secrets && cd secrets"
Enter
Type@1ms "age-keygen -o k 2>/dev/null"
Enter
Type@1ms "export SOPS_AGE_KEY_FILE=$PWD/k"
Enter
Type@1ms "PUB=$(age-keygen -y k)"
Enter
Type@1ms `printf 'creation_rules:\n  - path_regex: (prod|dev)\\.yaml$\n    age: %s\n' "$PUB" > .sops.yaml`
Enter
Type@1ms `echo "db_password: prod-pass-2026" > prod.yaml`
Enter
Type@1ms `echo "db_password: dev-pass-2026" > dev.yaml`
Enter
Type@1ms `PROMPT='%F{green}➜%f  %F{cyan}~/secrets%f '`
Enter
Type@1ms "clear"
Enter
Show

Type "head -3 .sops.yaml prod.yaml dev.yaml"
Enter
Sleep 3500ms

Type "cipher fix ."
Enter
Sleep 3000ms

Type "head -1 prod.yaml dev.yaml"
Enter
Sleep 3500ms
