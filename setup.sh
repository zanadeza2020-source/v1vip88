#!/data/data/com.termux/files/usr/bin/bash
echo "Installing MedTerm Final..."
cd "$(dirname "$0")/backend"
npm install
echo "Done! Edit .env then: bash start.sh"
