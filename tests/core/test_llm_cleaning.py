import re
import unittest


def clean_llm_output_regex(text):
    # This is the logic we plan to inject
    # Remove leading ```<language>
    # The flag re.MULTILINE is not needed for ^ if we want start of string,
    # but LLM might output newlines first. Let's stick to simple strip first.
    text = text.strip()

    # Regex for start block: ^```[a-zA-Z0-9+]*\s*
    # We use re.sub with care.
    text = re.sub(r"^```[a-zA-Z0-9+-]*\s*", "", text)

    # Regex for end block: ```$ (allow trailing whitespace)
    text = re.sub(r"\s*```$", "", text)

    return text.strip()


class TestLLMCleaning(unittest.TestCase):
    def test_clean_html_block(self):
        raw = "```html\n<!DOCTYPE html>\n<html>...</html>\n```"
        expected = "<!DOCTYPE html>\n<html>...</html>"
        self.assertEqual(clean_llm_output_regex(raw), expected)

    def test_clean_json_block(self):
        raw = '```json\n{"foo": "bar"}\n```'
        expected = '{"foo": "bar"}'
        self.assertEqual(clean_llm_output_regex(raw), expected)

    def test_clean_python_block(self):
        raw = "```python\nprint('hello')\n```"
        expected = "print('hello')"
        self.assertEqual(clean_llm_output_regex(raw), expected)

    def test_clean_cpp_block(self):
        raw = "```cpp\nint main() { return 0; }\n```"
        expected = "int main() { return 0; }"
        self.assertEqual(clean_llm_output_regex(raw), expected)

    def test_clean_no_fences(self):
        raw = "Just plain text."
        expected = "Just plain text."
        self.assertEqual(clean_llm_output_regex(raw), expected)

    def test_clean_with_internal_ticks(self):
        raw = "Here is a command: `ls -la`."
        expected = "Here is a command: `ls -la`."
        self.assertEqual(clean_llm_output_regex(raw), expected)

    def test_clean_triple_ticks_inside(self):
        # This is tricky. If the content actually contains a code block, we probably want to keep it?
        # Usually file content generation returns the file content ONLY.
        # But if it's a chat response, it might have blocks.
        # However, the user issue is about "generating content" (file content).
        # We assume the OUTERMOST blocks are the wrapper.
        raw = "```markdown\n# Title\n\nCode:\n```bash\nls\n```\nEnd\n```"
        # Leading ```markdown removed.
        # Trailing ``` removed.
        # Inner ```bash ... ``` kept.
        expected = "# Title\n\nCode:\n```bash\nls\n```\nEnd"
        self.assertEqual(clean_llm_output_regex(raw), expected)


if __name__ == "__main__":
    unittest.main()
