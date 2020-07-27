#!/bin/bash

pushd /home/ubuntu/cadre-login
source venv/bin/activate
exec python run_backend.py
