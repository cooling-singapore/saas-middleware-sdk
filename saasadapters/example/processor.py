import json
import logging
import os
import sys
import time

logger = logging.getLogger('example-processor')


def function(working_directory):
    print(f"trigger:progress:0")

    a_path = os.path.join(working_directory, 'a')
    with open(a_path, 'r') as f:
        a = json.load(f)
        a = a['v']
    print(f"a={a}")
    print(f"trigger:progress:20")
    time.sleep(0.2)

    b_path = os.path.join(working_directory, 'b')
    with open(b_path, 'r') as f:
        b = json.load(f)
        b = b['v']
    print(f"b={b}")
    print(f"trigger:progress:40")
    time.sleep(0.2)

    c = {
        'v': a + b
    }
    print(f"c={c}")
    print(f"trigger:progress:60")
    time.sleep(0.2)

    c_path = os.path.join(working_directory, 'c')
    with open(c_path, 'w') as f:
        json.dump(c, f, indent=4, sort_keys=True)
    print(f"trigger:progress:80")
    print(f"trigger:output:c")
    time.sleep(0.2)

    print(f"trigger:progress:100")


if __name__ == '__main__':
    function(sys.argv[1])
