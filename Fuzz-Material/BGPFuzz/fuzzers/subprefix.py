
from fuzzingbook.Fuzzer import Fuzzer
import ipaddress
import re
import random
from prefix import get_prefix

class SubPrefixFuzzer(Fuzzer):
    def __init__(self, seed, telnet_port):
        self.seed = seed
        self.telnet_port = telnet_port
        self.reset()

    def reset(self):
        self.population = self.seed
        self.seed_index = 0

    def get_subprefix(self, prefix):
        if prefix.prefixlen >= 30:
            return None
        return list(prefix.subnets(new_prefix=prefix.prefixlen + 2))[0]

    def mutate(self, inp, pfxs):
        lines = inp.splitlines()
        result = []
        inserted = False
        info = ""
        for line in lines:
            result.append(line)
            if not inserted:
                match = re.match(r'\s*network\s+(\d+\.\d+\.\d+\.\d+)(?:\s+mask\s+(\d+\.\d+\.\d+\.\d+))?', line)
                if match and pfxs:
                    candidates = [p for p in pfxs if p.prefixlen < 30]
                    if not candidates:
                        continue
                    base = random.choice(candidates)
                    sub = self.get_subprefix(base)
                    if sub:
                        sub_ip = str(sub.network_address)
                        sub_mask = str(sub.netmask)
                        indent = re.match(r'^(\s*)', line).group(1)
                        result.append(f"{indent}network {sub_ip} mask {sub_mask}")
                        inserted = True
                        info = f"Inserted sub-prefix {sub} from {base}"
        return '\n'.join(result), info if inserted else "no sub-prefix inserted"

    def fuzz(self):
        pfxs = [ipaddress.IPv4Network(p) for p in get_prefix(self.telnet_port)]
        if self.seed_index < len(self.seed):
            self.inp = self.seed[self.seed_index]
            self.seed_index += 1
        else:
            self.inp, _ = self.mutate(random.choice(self.population), pfxs)
        return self.mutate(self.inp, pfxs)
