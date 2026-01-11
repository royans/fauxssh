from ssh_honeypot.handlers.base import BaseHandler

class CatCommand(BaseHandler):
    def handle(self, cmd, context):
        if context.get('stdin'):
             return context['stdin'], {}, {'source': 'pipe', 'cached': False}
             
        if '--help' in cmd:
             return """Usage: cat [OPTION]... [FILE]...
Concatenate FILE(s) to standard output.

With no FILE, or when FILE is -, read standard input.

  -A, --show-all           equivalent to -vET
  -b, --number-nonblank    number nonempty output lines, overrides -n
  -e                       equivalent to -vE
  -E, --show-ends          display $ at end of each line
  -n, --number             number all output lines
  -s, --squeeze-blank      suppress repeated empty output lines
  -t                       equivalent to -vT
  -T, --show-tabs          display TAB characters as ^I
  -u                       (ignored)
  -v, --show-nonprinting   use ^ and M- notation, except for LFD and TAB
      --help        display this help and exit
      --version     output version information and exit

Examples:
  cat f - g  Output f's contents, then standard input, then g's contents.
  cat        Copy standard input to standard output.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation <https://www.gnu.org/software/coreutils/cat>
or available locally via: info '(coreutils) cat invocation'
""", {}, {}

        parts = cmd.split()
        # Simplistic parsing: take last arg as filename
        target_path = parts[-1] if len(parts) > 1 else ""
        
        # Interactive cat (no args) not supported, return empty for now
        if not target_path: return "", {}, {} 
        
        content, source = self._generate_or_get_content("cat", target_path, context)
        return content + "\n", {}, {'source': source, 'cached': source == 'local'}
