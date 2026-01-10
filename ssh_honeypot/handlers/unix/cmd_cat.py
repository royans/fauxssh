from ssh_honeypot.handlers.base import BaseHandler

class CatCommand(BaseHandler):
    def handle(self, cmd, context):
        if context.get('stdin'):
             return context['stdin'], {}, {'source': 'pipe', 'cached': False}
             
        parts = cmd.split()
        # Simplistic parsing: take last arg as filename
        target_path = parts[-1] if len(parts) > 1 else ""
        
        # Interactive cat (no args) not supported, return empty for now
        if not target_path: return "", {}, {} 
        
        content, source = self._generate_or_get_content("cat", target_path, context)
        return content + "\n", {}, {'source': source, 'cached': source == 'local'}
