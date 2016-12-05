## Overview
- `explore.py`: main script, line-by-line exploration
- `run.py`: main script, non line-by-line exploration
- `executor.py`: a line-by-line executor
- `factory.py`: some functions to build different kinds of symbolic memories
- `executor_config.py`: parser for executor config
- `simple_fully_symbolic_memory.py`: an angr-like implementation of a fully symbolic memory
- `angr_symbolic_memory.py`: a wrapper around angr symbolic memory
- `naive_fully_symbolic_memory.py`: a naive implementation of a fully symbolic memory (see: pseudocode/naive-v2)
- `utils.py`: other useful stuff
- `tests/`: testing binaries

## How to run
Line-by-line symbolic execution can be started with:

    python explore.py <path-to-binary>
    
Or (non line-by-line exploration):

    python run.py <path-to-binary>

The implementation of the symbolic memory can be selected by adding a parameter when calling `run.py` or `explore.py`. For instance:

     python explore.py 0 <path-to-binary>

Accepted values:
- `0`: `simple_fully_symbolic_memory.py` (default)
- `1`: `angr_symbolic_memory.py`
- `2`: `naive_fully_symbolic_memory.py`
    
## Binary configuration
For each binary, a configuration script `<path-to-binary>.py` must exist. This script must define few python functions:

    def start():
      return <start_address>

    def end():
      return [<end_address>, ...]

    def avoid():
      return [<avoid_address>, ...]

    def do_start(state):
      # properly initialize the initial state
      return stuff

    def do_end(state, stuff):
      # this is called when one of end targets is reached
