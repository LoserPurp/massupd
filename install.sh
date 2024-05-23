#!/bin/bash

# Navigate to the massupd folder
cd massupd || { echo "Failed to change directory to massupd"; exit 1; }

# Install pip requirements
if [ -f requirements.txt ]; then
  pip install -r requirements.txt || { echo "Failed to install pip requirements"; exit 1; }
else
  echo "requirements.txt not found"
  exit 1
fi

# Move massupd script to /usr/bin/massupd
if [ -f massupd ]; then
  sudo mv massupd /usr/bin/massupd || { echo "Failed to move massupd script to /usr/bin"; exit 1; }
else
  echo "massupd script not found"
  exit 1
fi

# Move the massupd folder to /usr/lib/massupd
cd .. || { echo "Failed to change directory to parent"; exit 1; }
sudo mv massupd /usr/lib/massupd || { echo "Failed to move massupd folder to /usr/lib"; exit 1; }

echo "Installation completed successfully"