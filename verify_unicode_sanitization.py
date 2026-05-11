import importlib.util
import sys

def import_scanner(filename):
    spec = importlib.util.spec_from_file_location("scanner", filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def test_sanitization(filename):
    print(f"\nTesting {filename} for Unicode sanitization...")
    mod = import_scanner(filename)

    # Test cases: (input, expected_output, description)
    test_cases = [
        ("hello\xadworld", "helloworld", "Soft hyphen"),
        ("hello\u200bworld", "helloworld", "Zero-width space"),
        ("hello\u200cworld", "helloworld", "Zero-width non-joiner"),
        ("hello\u200dworld", "helloworld", "Zero-width joiner"),
        ("hello\u200eworld", "helloworld", "Left-to-right mark"),
        ("hello\u200fworld", "helloworld", "Right-to-left mark"),
        ("hello\u2060world", "helloworld", "Word joiner"),
        ("hello\u2066world", "helloworld", "Left-to-right isolate (Bidi)"),
        ("hello\ufeffworld", "helloworld", "BOM / Zero-width no-break space"),
        ("hello\nworld", "helloworld", "Newline (existing protection)"),
        ("\x1b[31mhello\x1b[0m", "hello", "ANSI escape (existing protection)"),
    ]

    all_passed = True
    for input_text, expected, desc in test_cases:
        sanitized = mod.sanitize_text(input_text)
        if sanitized == expected:
            print(f"  ✅ PASSED: {desc}")
        else:
            print(f"  ❌ FAILED: {desc}")
            print(f"     Input:    {repr(input_text)}")
            print(f"     Expected: {repr(expected)}")
            print(f"     Got:      {repr(sanitized)}")
            all_passed = False

    return all_passed

if __name__ == "__main__":
    v1_ok = test_sanitization("Ollama_Scanner.py")
    v2_ok = test_sanitization("Ollama_Scanner_v4.2.py")

    if v1_ok and v2_ok:
        print("\n✨ All sanitization tests passed!")
        sys.exit(0)
    else:
        print("\n🚨 Some sanitization tests failed!")
        sys.exit(1)
