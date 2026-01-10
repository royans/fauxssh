from ssh_honeypot.handlers.base import BaseHandler

class HeadCommand(BaseHandler):
    def handle(self, cmd, context):
        parts = cmd.split()
        num_lines = 10
        files = []
        
        # Parse args manually similar to other handlers
        i = 1
        while i < len(parts):
            arg = parts[i]
            if arg.startswith('-n'):
                if arg == '-n':
                    if i + 1 < len(parts):
                        try:
                            num_lines = int(parts[i+1])
                            i += 2
                            continue
                        except: pass
                else:
                    try:
                        num_lines = int(arg[2:])
                    except: pass
            elif arg.startswith('-') and len(arg) > 1 and arg[1:].isdigit():
                 try:
                     num_lines = int(arg[1:])
                 except: pass
            elif not arg.startswith('-'):
                files.append(arg)
            i += 1
            
        content = ""
        # If no files, use stdin
        if not files:
            content = context.get('stdin', '')
        else:
            # First file only for simplicity
            target_path = files[0] # Use local var
            c, src = self._generate_or_get_content("head", target_path, context)
            content = c
            
        lines = content.splitlines(keepends=True)
        return "".join(lines[:num_lines]), {}, {'source': 'local', 'cached': False}
