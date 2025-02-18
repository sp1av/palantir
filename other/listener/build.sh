#!/bin/bash

pyinstaller --onefile listener.py 

staticx ./dist/listener ./listener.bin
