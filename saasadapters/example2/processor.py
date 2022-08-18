import json
import logging
import os
import sys
import time

logger = logging.getLogger('example-processor-2')


def function(working_directory):
    print(f"trigger:progress:0")

    parameters_path = os.path.join(working_directory, 'parameters')
    with open(parameters_path, 'r') as f:
        parameters = json.load(f)

    # calculate the result
    a = parameters['a']
    b = parameters['b']
    c = {
        'v': a + b
    }
    print(f"c={c}")
    print(f"trigger:progress:40")

    # simply wait for a while...
    delay = parameters['delay']
    time.sleep(delay)

    c_path = os.path.join(working_directory, 'c')
    with open(c_path, 'w') as f:
        json.dump(c, f, indent=4, sort_keys=True)
    print(f"trigger:progress:80")
    print(f"trigger:output:c")

    print(f"trigger:progress:100")


if __name__ == '__main__':
    function(sys.argv[1])
