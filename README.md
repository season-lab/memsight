Files:
- `run.py`: main
- `executor.py`: a line-by-line executor
- `ececutor_config.py`: parser for executor config
- `simple_fully_symbolic_memory.py`: an angr-like implementation of a fully symbolic memory
- `utils.py`: other useful stuff
- `tests/`: testing binaries


Symbolic execution can be started with:

    python run.py <path-to-binary>
    
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
