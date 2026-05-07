#!/bin/bash
echo "Stopping DVWA..."
sudo docker stop dvwa-test 2>/dev/null
echo "Stopping Docker Engine..."
sudo systemctl stop docker
sudo systemctl stop docker.socket
echo "All tools stopped."