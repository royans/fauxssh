from ssh_honeypot.handlers.base import BaseHandler
import shlex
import re

class GrepCommand(BaseHandler):
    def handle(self, cmd, context):
        try:
            parts = shlex.split(cmd)
        except:
            parts = cmd.split()
            
        if len(parts) < 2: return "", {}, {}
        
        content = ""
        source = 'local'
        grep_cmd_for_parsing = cmd

        if context.get('stdin'):
            content = context['stdin']
            source = 'pipe'
        else:
            if len(parts) < 3: return "", {}, {'source': 'local', 'cached': False}
            target_path = parts[-1]
            content, source = self._generate_or_get_content("grep", target_path, context)
            
            # Remove filename from cmd so _simple_grep parses pattern correctly from last arg
            # E.g. "grep -i pattern file" -> "grep -i pattern"
            # Using simple join to match original behavior, though shlex.join is better
            grep_cmd_for_parsing = ' '.join(parts[:-1])

        result_text = self._simple_grep(content, grep_cmd_for_parsing)
        if result_text and not result_text.endswith('\n'):
             result_text += '\n'
             
        return result_text, {}, {'source': source, 'cached': source == 'local'}

    def _simple_grep(self, text, grep_cmd):
        """
        Rudimentary grep implementation for VFS checks.
        Supports: grep pattern, -i, -v, -E (regex), -m N (max count)
        """
        try:
            args = shlex.split(grep_cmd)
        except:
            args = grep_cmd.split()
            
        if len(args) < 2: return text
        
        # Naive Argument Parsing
        case_insensitive = '-i' in args
        invert = '-v' in args
        use_regex = '-E' in args or '--extended-regexp' in args
        
        max_count = None
        pattern = None
        
        # Iterate to find flags and pattern
        # Skip 'grep' (args[0])
        i = 1
        while i < len(args):
            arg = args[i]
            
            if arg == '-i' or arg == '-v' or arg == '-E' or arg == '--extended-regexp':
                i += 1
                continue
                
            if arg.startswith('-m'):
                if arg == '-m':
                    if i + 1 < len(args):
                        try:
                            max_count = int(args[i+1])
                            i += 1
                        except: pass
                else:
                    try:
                        max_count = int(arg[2:])
                    except: pass
                i += 1
                continue
            
            if arg.startswith('-') and len(arg) > 1:
                # Handle combined flags roughly? e.g. -iv
                pass
                
            # If not a flag, assume Pattern (first positional)
            if pattern is None and not arg.startswith('-'):
                pattern = arg
            
            i += 1

        if pattern is None:
             # Fallback: Last arg?
             pattern = args[-1]
        
        filtered = []
        count = 0
        
        # Pre-compile regex if needed
        regex_obj = None
        if use_regex:
            flags = 0
            if case_insensitive: flags |= re.IGNORECASE
            try:
                regex_obj = re.compile(pattern, flags)
            except:
                pass 
        
        for line in text.splitlines():
            # Strip ANSI for matching check (keep in output)
            clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line)
            
            match = False
            
            if regex_obj:
                if regex_obj.search(clean_line):
                    match = True
            else:
                # Substring match
                check_l = clean_line
                check_p = pattern
                if case_insensitive:
                    check_l = check_l.lower()
                    check_p = check_p.lower()
                
                if check_p in check_l:
                    match = True
            
            if invert:
                match = not match
            
            if match:
                filtered.append(line)
                count += 1
                if max_count is not None and count >= max_count:
                    break
        
        return '\n'.join(filtered)
