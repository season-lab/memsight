`run.py` is both an implementation of a fully symbolic memory and a line-by-line executor. `tests/` contains few binaries.

Symbolic execution can be started with:

    python run.py <path-to-binary>
    
For each binary, a configuration script `<path-to-binary>.py` must exist. This script should define few python functions:

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
