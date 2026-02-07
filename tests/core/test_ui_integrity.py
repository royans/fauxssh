import os
import re
import html.parser
import ast
import pytest
from ssh_honeypot.core.utils import PROJECT_ROOT

ASSETS_DIR = os.path.join(
    PROJECT_ROOT, "ssh_honeypot", "services", "http_server", "assets"
)


class IntegrityHTMLParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        # void elements do not need closing tags
        void_elements = {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        }
        if tag not in void_elements:
            self.tags.append(tag)

    def handle_endtag(self, tag):
        if not self.tags:
            self.errors.append(f"Unexpected end tag: </{tag}> (no tags open)")
            return

        last_tag = self.tags.pop()
        if last_tag != tag:
            self.errors.append(
                f"Mismatched end tag: expected </{last_tag}>, but found </{tag}>"
            )


def validate_html_file(filepath):
    """Basic HTML well-formedness check."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    parser = IntegrityHTMLParser()
    try:
        parser.feed(content)
    except Exception as e:
        return [f"HTML Parser Error: {e}"]

    errors = parser.errors
    if parser.tags:
        errors.append(f"Unclosed tags at end of file: {', '.join(parser.tags)}")

    return errors


def validate_vue_expressions(filepath):
    """Check for common Vue template expression errors."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    errors = []
    # Find all {{ ... }} blocks
    # Using [^{}]* to avoid greedy matching over multiple blocks,
    # but we need to handle nested braces if any (unlikely in this app)
    # The split-line error I had was like {{ foo || 'bar\n baz' }}

    # regex for {{ ... }} matches
    pattern = re.compile(r"\{\{(.*?)\}\}", re.DOTALL)

    for match in pattern.finditer(content):
        expr = match.group(1).strip()
        line_num = content.count("\n", 0, match.start()) + 1

        # 1. Check for newlines within string literals that aren't template literals
        # This is a bit complex with regex, but we can try basic JS-like checks
        if "\n" in expr:
            # Check if the newline is inside a quoted string that's NOT a backtick string
            # FauxSSH templates mostly use ' or "
            # If a line breaks in the middle of a '...', Vue/JS will complain unless escaped
            # The recent error was exactly this.

            # Simple check: if there's a newline, try to parse it with ast.parse to see if it's valid python (often maps well to simple JS)
            # or just flag newlines in {{ }} as suspicious since we prefer single-line or properly escaped

            # Let's try to detect if it's a split string literal
            lines = expr.split("\n")
            for i, line in enumerate(lines):
                # Count quotes on this line
                s_quotes = line.count("'") - line.count("\\'")
                d_quotes = line.count('"') - line.count('\\"')
                if s_quotes % 2 != 0 or d_quotes % 2 != 0:
                    errors.append(
                        f"Line {line_num + i}: Potential split string literal or unclosed quote in Vue expression: {expr[:50]}..."
                    )
                    break

        # 2. Check for balance of quotes in the whole expression
        if (expr.count("'") - expr.count("\\'")) % 2 != 0:
            errors.append(
                f"Line {line_num}: Unbalanced single quotes in expression: {expr[:50]}..."
            )
        if (expr.count('"') - expr.count('\\"')) % 2 != 0:
            errors.append(
                f"Line {line_num}: Unbalanced double quotes in expression: {expr[:50]}..."
            )

    return errors


# Find all .html files in assets directory
html_files = [f for f in os.listdir(ASSETS_DIR) if f.endswith(".html")]


@pytest.mark.parametrize("filename", html_files)
def test_html_assets_integrity(filename):
    filepath = os.path.join(ASSETS_DIR, filename)
    assert os.path.exists(filepath), f"Asset missing: {filepath}"

    # Validate HTML structure
    html_errors = validate_html_file(filepath)
    assert not html_errors, f"HTML integrity issues in {filename}:\n" + "\n".join(
        html_errors
    )

    # Validate Vue expressions
    vue_errors = validate_vue_expressions(filepath)
    assert not vue_errors, f"Vue template issues in {filename}:\n" + "\n".join(
        vue_errors
    )
