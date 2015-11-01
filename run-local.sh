#!/bin/sh
export DATABASE_URL="sqlite:///tsuru2d.db"
export PORT="8080"
python3 tsuru2d-server.py
