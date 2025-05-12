from fuzzingbook.Fuzzer import Fuzzer
import re
import random

def force_max_prefix_one(config: str):
    pattern = re.compile(r'(neighbor\s+\d{1,3}(?:\.\d{1,3}){3}\s+maximum-prefix\s+)(\d+)(\s+\d+)', re.IGNORECASE)
    mutated_part = None

    def replacer(match):
        nonlocal mutated_part
        before = match.group(0)
        after = match.group(1) + "1" + match.group(3)
        mutated_part = f"{before} -> {after}"
        return after

    mutated_config = pattern.sub(replacer, config)
    return mutated_config, mutated_part

class MaxPrefixFuzzer(Fuzzer):
    def __init__(self, seed):
        self.seed = seed
        self.reset()

    def reset(self):
        self.population = self.seed
        self.seed_index = 0

    def mutate(self, inp):
        return force_max_prefix_one(inp)

    def fuzz(self):
        if self.seed_index < len(self.seed):
            self.inp = self.seed[self.seed_index]
            self.seed_index += 1
        else:
            self.inp, _ = self.mutate(random.choice(self.population))
        return self.mutate(self.inp)
