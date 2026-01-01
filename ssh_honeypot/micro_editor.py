class MicroEditor:
    def __init__(self, chan, filename, initial_content=""):
        self.chan = chan
        self.filename = filename
        self.lines = initial_content.split('\n') if initial_content else [""]
        self.cy = 0 # Cursor Y
        self.cx = 0 # Cursor X
        self.scroll_y = 0
        self.running = True
        
    def refresh(self):
        # Clear Screen
        self.chan.send(b'\033[2J\033[H')
        
        # Header
        header = f"  MICRO EDITOR v1.1  File: {self.filename}".center(80)
        self.chan.send(f"\033[47;30m{header}\033[0m\r\n")
        
        # Content (Simple render)
        rows, cols = 24, 80 # Assume standard
        for i in range(rows - 2):
            idx = self.scroll_y + i
            if idx < len(self.lines):
                line = self.lines[idx]
                self.chan.send(f"{line}\r\n")
            else:
                self.chan.send("~\r\n")
                
        # Footer
        footer = "^X Exit  ^S Save"
        self.chan.send(f"\033[47;30m{footer.ljust(80)}\033[0m")
        
        # Move Cursor
        # ANSI: Esc[line;colH
        # Line is 2 + (cy - scroll_y). Col is 1 + cx
        screen_y = 2 + (self.cy - self.scroll_y)
        screen_x = 1 + self.cx
        self.chan.send(f"\033[{screen_y};{screen_x}H")
        
    def run(self):
        self.refresh()
        while self.running:
            char = self.chan.recv(1)
            if not char: break
            
            # Ctrl+X (Exit)
            if char == b'\x18': 
                self.running = False
                return None
                
            # Ctrl+S (Save)
            if char == b'\x13':
                self.running = False
                return "\n".join(self.lines)

            # Enter
            if char == b'\r':
                current_line = self.lines[self.cy]
                new_line = current_line[self.cx:]
                self.lines[self.cy] = current_line[:self.cx]
                self.lines.insert(self.cy + 1, new_line)
                self.cy += 1
                self.cx = 0
                self.refresh()
                
            # Backspace (127 or 8)
            elif char == b'\x7f' or char == b'\x08':
                if self.cx > 0:
                    line = self.lines[self.cy]
                    self.lines[self.cy] = line[:self.cx-1] + line[self.cx:]
                    self.cx -= 1
                    self.refresh()
                elif self.cy > 0:
                    # Merge with previous line
                    curr = self.lines.pop(self.cy)
                    self.cy -= 1
                    self.cx = len(self.lines[self.cy])
                    self.lines[self.cy] += curr
                    self.refresh()

            # Arrow Keys (Escape Sequence) support 
            elif char == b'\x1b':
                try:
                    seq = self.chan.recv(2)
                    if seq == b'[A': # Up
                        if self.cy > 0:
                            self.cy -= 1
                            if self.cx > len(self.lines[self.cy]): 
                                self.cx = len(self.lines[self.cy])
                    elif seq == b'[B': # Down
                        if self.cy < len(self.lines) - 1:
                            self.cy += 1
                            if self.cx > len(self.lines[self.cy]):
                                self.cx = len(self.lines[self.cy])
                    elif seq == b'[C': # Right
                        if self.cx < len(self.lines[self.cy]):
                            self.cx += 1
                    elif seq == b'[D': # Left
                        if self.cx > 0:
                            self.cx -= 1
                    self.refresh()
                except:
                    pass

            # Normal Char
            elif char >= b' ' and char <= b'~':
                c = char.decode('utf-8')
                line = self.lines[self.cy]
                self.lines[self.cy] = line[:self.cx] + c + line[self.cx:]
                self.cx += 1
                self.refresh()
