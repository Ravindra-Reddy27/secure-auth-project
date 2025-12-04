#!/bin/sh

# Start the cron daemon in the background.
# The `&` symbol is crucial here.
echo "Starting cron service..."
cron -f &

# Keep the web server in the foreground, making it the main container process.
echo "Starting Uvicorn server..."
exec uvicorn main:app --host 0.0.0.0 --port 8080