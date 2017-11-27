[![Build Status](https://travis-ci.com/season-lab/fully-symbolic-memory.svg?token=aY5YvgCjsjn9EnyWAi6e&branch=master)](https://travis-ci.com/season-lab/fully-symbolic-memory)

## Overview

- `explore.py`: main script, line-by-line exploration
- `run.py`: main script, non line-by-line exploration
- `executor/`: common code to perform exploration
- `executor/executor_config.py`: parser for executor config
- `memory/`: some memory implememtations and their dependencies (data structures)
- `memory/angr_symbolic_memory.py`: a wrapper around angr symbolic memory
- `memory/range_fully_symbolic_memory.py`: memsight, an implementation of a fully symbolic memory (see: [pseudocode/naive-v4](pseudocode/naive-v4/main.pdf))
- `utils.py`: other useful stuff
- `tests/`: testing binaries

## How to run
`run.py` and `explore.py` can be used to run angr on a metabinary.

Line-by-line symbolic execution can be started with:

    python explore.py <path-to-metabinary>
    
Or (non line-by-line exploration):

    python run.py <path-to-metabinary>

The implementation of the symbolic memory can be selected by adding a parameter when calling `run.py` or `explore.py`. For instance:

     python explore.py <id> <path-to-metabinary>

Where `id` can be:
- `0`: `angr_symbolic_memory.py`
- `1`: `range_fully_symbolic_memory.py` (memsight)
    
## MetaBinary configuration
A metabinary is a: binary + executor configuration.

For each binary, a configuration script `<binary>.py` must exist. This script must define few python functions:

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
    
