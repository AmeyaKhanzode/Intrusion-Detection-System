#!/bin/bash
# to start first window to show tcp packets
tmux new-session -d -s ids_session
sleep 0.1
tmux send-keys -t ids_session "sudo python3 packet_sniffer.py" C-m
tmux split-window -h -t ids_session
sleep 0.1
tmux send-keys -t ids_session:0.1 "nc -lvnp 9090" C-m
tmux split-window -v -t ids_session
sleep 0.1
tmux send-keys -t ids_session:0.2 "echo 'sup lalith, isnt this kinda cool' | nc 127.0.0.1 9090" C-m

# to start second window to detect brute force
tmux new-window -t ids_session
sleep 0.1
tmux send-keys -t ids_session:1.0 "sudo python3 packet_sniffer.py" C-m
tmux split-window -h -t ids_session:1
sleep 0.1
tmux send-keys -t ids_session:1.1 "cd ~/CN_Project/Intrusion-Detection-System/detection/" C-m
sleep 0.1
tmux send-keys -t ids_session:1.1 "sudo python3 brute_force_detector.py" C-m
tmux split-window -v -t ids_session:1
sleep 0.2
tmux send-keys -t ids_session:1.2 "sudo hping3 -S -i u1000 -p 22 127.0.0.1" C-m

tmux select-window -t ids_session:0
tmux attach -t ids_session
