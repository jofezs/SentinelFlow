# Records docs/demo.gif with VHS (https://github.com/charmbracelet/vhs) against the running
# Docker Compose stack. Regenerate with:  scripts/record-demo.sh
Output docs/demo.gif

Set Shell bash
Set FontSize 16
Set Width 1040
Set Height 960
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 45ms

Hide
Type "cd /vhs && export PS1='$ ' && clear"
Enter
Show

Sleep 600ms
Type "python3 scripts/demo.py"
Sleep 700ms
Enter
Wait+Screen@120s /refused/
Sleep 5s
