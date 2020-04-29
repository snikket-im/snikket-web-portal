#!/bin/sh

exec hypercorn -b "0.0.0.0:8000" snikket_web:app
