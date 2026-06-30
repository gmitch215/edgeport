#!/bin/sh
# provisions PASSWORD-required sudo for the tester user so the sudo integration tests
# exercise the real `sudo -S` password-prompt path (not a NOPASSWD bypass).
# linuxserver runs /custom-cont-init.d scripts as root after the user is created.
set -e

apk add --no-cache sudo >/dev/null 2>&1 || true

# make sure the unix account password matches the SSH password (sudo authenticates via PAM)
echo 'tester:testpass' | chpasswd 2>/dev/null || true

# require a password (no NOPASSWD); alpine sudo leaves requiretty off by default, which is
# what lets `sudo -S` read the password from stdin over a tty-less exec channel
echo 'tester ALL=(ALL) ALL' > /etc/sudoers.d/tester
chmod 0440 /etc/sudoers.d/tester
