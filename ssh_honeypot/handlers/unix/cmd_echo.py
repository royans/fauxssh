import shlex
import codecs


def handle_echo(cmd, context):
    """
    Enhanced echo handler with support for -e (interpret backslash escapes).
    """
    parts = []
    try:
        parts = shlex.split(cmd)
    except Exception:
        # Fallback for simple split if shlex fails (e.g. unmatched quotes)
        parts = cmd.split()

    if not parts:
        return "\n", {}, {"source": "handler", "cached": False}

    # parts[0] is 'echo'
    args = parts[1:]

    interpret_escapes = False

    # Check for -e flag
    # Note: echo -e "foo" -> args=['-e', 'foo']
    # We should handle multiple flags if necessary, but -e is the main one.
    # GNU echo supports -n (no newline) and -e (enable interpretation of backslash escapes)
    # `-E` (disable interpretation) is default.

    no_newline = False

    # Simple flag parsing
    clean_args = []
    for arg in args:
        if arg == "-e":
            interpret_escapes = True
        elif arg == "-n":
            no_newline = True
        elif arg == "-ne" or arg == "-en":
            interpret_escapes = True
            no_newline = True
        elif arg.startswith("-") and all(c in "neE" for c in arg[1:]):
            # Handle combined flags like -ne
            if "n" in arg:
                no_newline = True
            if "e" in arg:
                interpret_escapes = True
            if "E" in arg:
                interpret_escapes = False
        else:
            clean_args.append(arg)

    # Reassemble string
    # shlex.split removes quotes.
    # We join with spaces.
    content = " ".join(clean_args)

    if interpret_escapes:
        try:
            # Decode unicode_escape to interpret \x61, \n, etc.
            # However, unicode_escape might encode things we don't want or behave slightly differently.
            # But for \xHH and \n it is usually correct.
            content = codecs.decode(content, "unicode_escape")
        except Exception:
            # Fallback if decode fails
            pass

    output = content
    if not no_newline:
        output += "\n"

    return output, {}, {"source": "handler", "cached": False}
