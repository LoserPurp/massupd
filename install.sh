#!/bin/bash

#Checks if the script is run as root
if [ "$EUID" -ne 0 ]
  then echo "You need to run the install script as root"
  exit
fi

#Navigates to the massupd folder
cd massupd || { echo "Failed to change directory to massupd (You need to run this script outside the massupd folder)"; exit 1; }

#Installs pip requirements
if [ -f requirements.txt ]; then
  pip install -r requirements.txt || { echo "Failed to install pip requirements"; exit 1; }
else
  echo "requirements.txt not found"
  exit 1
fi

#Moves massupd script to /usr/bin/massupd
if [ -f massupd ]; then
  mv massupd /usr/bin/massupd || { echo "Failed to move massupd script to /usr/bin"; exit 1; }
else
  echo "massupd script not found"
  exit 1
fi

#Moves the massupd folder to /usr/lib/massupd
cd .. || { echo "Failed to change directory to parent"; exit 1; }
mv massupd /usr/lib/massupd || { echo "Failed to move massupd folder to /usr/lib"; exit 1; }

#Makes script executeable
chmod +r /usr/bin/massupd

echo "Installation completed successfully"