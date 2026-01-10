from ssh_honeypot.handlers.base import BaseHandler
import shlex

class CutCommand(BaseHandler):
    def handle(self, cmd, context):
        parts = shlex.split(cmd)
        
        delim = "\t"
        fields_str = ""
        files = []
        
        i = 1
        while i < len(parts):
            arg = parts[i]
            if arg.startswith('-d'):
                if len(arg) > 2:
                    delim = arg[2:]
                elif i + 1 < len(parts):
                    delim = parts[i+1]
                    i += 1
            elif arg.startswith('-f'):
                if len(arg) > 2:
                    fields_str = arg[2:]
                elif i + 1 < len(parts):
                    fields_str = parts[i+1]
                    i += 1
            elif not arg.startswith('-'):
                files.append(arg)
            i += 1
            
        if not fields_str:
            return "cut: you must specify a list of bytes, characters, or fields\n", {}, {}
            
        indices = set()
        for group in fields_str.split(','):
            if '-' in group:
                start, end = group.split('-', 1)
                s = int(start) if start else 1
                e = int(end) if end else 1000
                for k in range(s, e + 1):
                    indices.add(k)
            else:
                try:
                    indices.add(int(group))
                except: pass
                
        content = ""
        if not files:
            content = context.get('stdin', '')
        else:
             target_path = files[0]
             c, src = self._generate_or_get_content("cut", target_path, context)
             content = c
        
        output_lines = []
        for line in content.splitlines():
            if delim in line:
                parts_line = line.split(delim)
                selected = []
                for idx in sorted(list(indices)):
                    if idx <= len(parts_line):
                        selected.append(parts_line[idx-1])
                output_lines.append(delim.join(selected))
            else:
                output_lines.append(line)
                
        return "\n".join(output_lines) + "\n", {}, {'source': 'local', 'cached': False}
