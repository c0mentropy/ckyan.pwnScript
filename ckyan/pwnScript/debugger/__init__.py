from ..connect import *


def ggdb(break_point: str = "", pie: int = 0):

    cmd = ""
    cmd += "#!/bin\n"
    cmd += ("gdb -p `pidof %s` -q " % connect_io.binary_path)

    if break_point and pie:
        cmd += f"-ex 'b *$rebase({break_point}) '"
    elif break_point and pie == 0:
        cmd += f"-ex 'b *{break_point} '"

    with open("./gdb.sh", 'w') as f:
        f.write(cmd)
    os.system("chmod +x ./gdb.sh")


def gdb_debugger(*, break_point: str = "", binary_path: str = "", enable_pie: bool = False) -> None:
    """
    Creates a GDB debugging script based on the provided parameters and makes it executable.

    :param break_point: The memory address or function name where the breakpoint should be set.
    :param binary_path: The path to the binary file being debugged.
    :param enable_pie: A boolean indicating whether to enable Position Independent Executables (PIE) support.
    :return None
    """

    if binary_path == '':
        binary_path = connect_io.binary_path

    # Ensure input parameters are safe and valid
    if not binary_path:
        print("Invalid break_point or binary_path.")
        return
    if not os.path.isfile(binary_path):
        print(f"Binary path '{binary_path}' does not exist.")
        return

    # Construct the GDB command safely
    cmd = ["gdb", "-p", f"`pidof {binary_path}`", "-q"]
    if break_point:
        ex_option = "-ex 'b *$rebase({})'".format(break_point) if enable_pie else "-ex 'b *{}'".format(break_point)
        cmd.append(ex_option)

    # Write the command to a script file
    script_file = "./gdb.sh"
    try:
        with open(script_file, 'w') as f:
            f.write("#!/bin/sh\n")
            f.write(" ".join(cmd))
    except IOError as e:
        print(f"Failed to write to script file: {e}")
        return

    # Make the script file executable
    try:
        os.chmod(script_file, 0o755)  # Use octal notation for clarity
    except OSError as e:
        print(f"Failed to change permissions of script file: {e}")


def ddebug():
    if connect_io.local and connect_io.tmux:
        gdb.attach(connect_io.conn)
        pause()


D = ddebug

if connect_io.local:
    gdb_debugger()

"""
if '.py' in sys.argv[0] or 'python' in sys.argv[0] and connect_io.local:
    gdb_debugger()
"""
