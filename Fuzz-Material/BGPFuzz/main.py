
from config import file_path, config_path, capture_file_name
from gns3_api import (
    get_project_and_links,
    get_config_file,
    upload_config_with_restart,
    reload_all_nodes,
    start_capture
)
from fuzzers.randomfuzz import MyBaselineFuzzer
from fuzzers.subprefix import SubPrefixFuzzer
from fuzzers.maxprefix import MaxPrefixFuzzer
from oracles.bug_oracles import oracle_duplicate_prefix
import time
import random


def choose_fuzzer(seed, telnet_port, weights=(0.3, 0.3, 0.4)):
    fuzzers = [
        lambda: SubPrefixFuzzer(seed, telnet_port),
        lambda: MaxPrefixFuzzer(seed),
        lambda: MyBaselineFuzzer(seed)
    ]
    return random.choices(fuzzers, weights=weights, k=1)[0]()

def run_fuzzing_cycle(project_id, node_id, link_id, config_path, original_config, telnet_port):
    fuzzer = choose_fuzzer(seed=[original_config], telnet_port=telnet_port, weights=(1, 0, 0))
    for i in range(5):
        print(f"\n--- Fuzzing Iteration {i + 1} ---")
        mutated_config, info = fuzzer.fuzz()
        print(f"Mutation applied: {info}")

        upload_config_with_restart(project_id, node_id, config_path, mutated_config)
        start_capture(project_id, link_id, capture_file_name=f"capture_{i+1}.pcap")
        time.sleep(60)

        result, pairs = oracle_duplicate_prefix(telnet_port)
        if result:
            print(f"[Oracle] Found {len(pairs)} suspicious prefix overlaps.")

            print("\n[Recovery Phase] Reloading all nodes to restore initial state...")
            upload_config_with_restart(project_id, node_id, config_path, original_config)
            reload_all_nodes(project_id)
            time.sleep(60)



def main():
    project_id, node_id, link_id, telnet_port, config_path = get_project_and_links(file_path)
    if not all([project_id, node_id, link_id]):
        return
    else:
        print(f"\nSelected Project ID: {project_id}")
        print(f"Selected Node ID: {node_id}")
        print(f"Selected Link ID: {link_id}")
        print(f"The Config Path: {config_path}")
        
    original_config = get_config_file(project_id, node_id, config_path)
    if not original_config:
        return

    run_fuzzing_cycle(project_id, node_id, link_id, config_path, original_config, telnet_port)
   

if __name__ == "__main__":
    main()



