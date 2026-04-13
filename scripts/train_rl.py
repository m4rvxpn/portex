#!/usr/bin/env python3
"""
Portex RL Training Sidecar
===========================
Trains a PPO policy for probe optimization using stable-baselines3.
Exposes a gRPC server for inference.

Usage:
    python3 train_rl.py --mode train --episodes 1000
    python3 train_rl.py --mode serve --model-path rl_policy.zip --port 50051
"""

import argparse
import json
import os
import sys
from typing import Dict, Any

import numpy as np

STATE_DIM = 12
ACTION_DIM = 8  # discrete action space

PORT_STATES = {
    "open": 1.0,
    "closed": 0.0,
    "filtered": 0.5,
    "open|filtered": 0.25,
    "unknown": 0.0,
}

ACTIONS = [
    {"scan_mode": "",      "timing_delta": 0,  "src_port": 0, "use_decoy": False, "switch_proto": ""},
    {"scan_mode": "syn",   "timing_delta": 0,  "src_port": 0, "use_decoy": False, "switch_proto": ""},
    {"scan_mode": "ack",   "timing_delta": 0,  "src_port": 0, "use_decoy": False, "switch_proto": ""},
    {"scan_mode": "udp",   "timing_delta": 0,  "src_port": 0, "use_decoy": False, "switch_proto": "udp"},
    {"scan_mode": "",      "timing_delta": -1, "src_port": 0, "use_decoy": False, "switch_proto": ""},
    {"scan_mode": "",      "timing_delta": 1,  "src_port": 0, "use_decoy": False, "switch_proto": ""},
    {"scan_mode": "",      "timing_delta": 0,  "src_port": 0, "use_decoy": True,  "switch_proto": ""},
    {"scan_mode": "fin",   "timing_delta": 0,  "src_port": 0, "use_decoy": False, "switch_proto": ""},
]


def state_to_vector(state: Dict[str, Any]) -> np.ndarray:
    """Convert a state dict to a normalized feature vector."""
    port = state.get("port", 0) / 65535.0
    port_state_val = PORT_STATES.get(state.get("port_state", ""), 0.0)
    response_time = min(state.get("response_time", 0.0) / 10000.0, 1.0)
    ttl = state.get("ttl", 0) / 255.0
    window = state.get("window_size", 0) / 65535.0
    filter_flags = state.get("filter_flags", 0)
    f_filtered = float((filter_flags >> 0) & 1)
    f_rst_storm = float((filter_flags >> 1) & 1)
    f_timeout = float((filter_flags >> 2) & 1)
    attempt = min(state.get("attempt", 0), 10) / 10.0
    proto_map = {"tcp": 0.33, "udp": 0.66, "sctp": 1.0}
    proto = proto_map.get(state.get("protocol", "tcp"), 0.0)
    has_prev = 1.0 if state.get("has_prev_action", False) else 0.0
    prev_timing = state.get("prev_timing_delta", 0) / 2.0 + 0.5

    return np.array([
        port, port_state_val, response_time, ttl, window,
        f_filtered, f_rst_storm, f_timeout, attempt, proto,
        has_prev, prev_timing
    ], dtype=np.float32)


def heuristic_policy(state_vec: np.ndarray) -> int:
    """Heuristic baseline: action index based on filter flags."""
    filtered = state_vec[5] > 0.5
    rst_storm = state_vec[6] > 0.5
    timeout = state_vec[7] > 0.5
    attempt = state_vec[8]

    if rst_storm:
        return 4  # slow down timing
    if filtered:
        return 7  # try FIN scan
    if timeout:
        return 3  # try UDP
    if attempt > 0.3:
        return 6  # use decoy
    return 0  # keep current


def train(episodes: int = 1000, model_path: str = "rl_policy.zip"):
    """Train a PPO policy. Requires stable-baselines3."""
    try:
        import gymnasium as gym
        from stable_baselines3 import PPO
        from stable_baselines3.common.env_util import make_vec_env
        print("stable-baselines3 available — starting PPO training")
        # A real training env would be PhantomEnv wrapping a scapy simulation.
        # For now we train on CartPole as a placeholder.
        env = make_vec_env("CartPole-v1", n_envs=4)
        model = PPO("MlpPolicy", env, verbose=1)
        model.learn(total_timesteps=episodes * 100)
        model.save(model_path)
        print(f"Model saved to {model_path}")
    except ImportError:
        print("stable-baselines3 not installed. pip install stable-baselines3")
        print("Running heuristic self-test instead...")
        # Test the heuristic policy
        test_states = [
            {"port": 80,  "port_state": "filtered", "filter_flags": 1},
            {"port": 22,  "port_state": "open",     "filter_flags": 0},
            {"port": 443, "port_state": "filtered", "filter_flags": 2},
        ]
        for s in test_states:
            vec = state_to_vector(s)
            action_idx = heuristic_policy(vec)
            print(f"State: {s['port_state']} port {s['port']} -> Action: {ACTIONS[action_idx]}")


def serve(model_path: str = None, port: int = 50051):
    """Run gRPC inference server. Requires grpcio + generated proto stubs."""
    try:
        import grpc
        print(f"gRPC server starting on port {port}")
        print("Note: Run 'protoc proto/rl_agent.proto --python_out=. --grpc_python_out=.' first")
        print("Placeholder server — integrate with generated stubs in production")
    except ImportError:
        print("grpcio not installed. pip install grpcio grpcio-tools")
        print(f"Would serve on port {port} with model: {model_path or 'heuristic'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Portex RL Training Sidecar")
    parser.add_argument("--mode", choices=["train", "serve", "test"], default="test")
    parser.add_argument("--episodes", type=int, default=1000)
    parser.add_argument("--model-path", default="rl_policy.zip")
    parser.add_argument("--port", type=int, default=50051)
    args = parser.parse_args()

    if args.mode == "train":
        train(args.episodes, args.model_path)
    elif args.mode == "serve":
        serve(args.model_path, args.port)
    else:  # test
        print("Running heuristic policy self-test...")
        train(episodes=0)
