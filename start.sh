#!/bin/bash

# Start a new tmux session in detached mode
tmux new-session -d -s ids_session -n main

# Pane 0: packet_sniffer.py
tmux send-keys -t ids_session:0.0 "sudo python3 packet_sniffer.py" C-m
sleep 0.2

# Split Pane 0 horizontally -> Pane 1 (right of Pane 0)
tmux split-window -h -t ids_session:0.0
sleep 0.2
# Pane 1: arp_spoofing.py
tmux send-keys -t ids_session:0.1 "cd ~/Intrusion-Detection-System/detection && sudo python3 arp_spoofing.py" C-m
sleep 0.2

# Split Pane 0 vertically -> Pane 2 (below Pane 0)
tmux split-window -v -t ids_session:0.0
sleep 0.2
tmux send-keys "cd ~/Intrusion-Detection-System/detection/" C-m
tmux send-keys "python3 brute_force_detector.py" C-m

sleep 0.2

tmux split-window -v -t ids_session:0.2
sleep 0.2
tmux send-keys "cd ~/Intrusion-Detection-System/detection/" C-m
tmux send-keys "python3 port_scan_detector.py" C-m

# Attach the session
tmux attach -t ids_session
