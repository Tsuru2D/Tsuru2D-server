#!/bin/sh
SCRIPT_PATH="tsuru2d-server.py"
export DATABASE_URL="sqlite:///tsuru2d.db"
export PORT="8080"
python3 $SCRIPT_PATH
