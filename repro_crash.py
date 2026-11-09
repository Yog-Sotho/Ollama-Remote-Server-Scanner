import asyncio
import aiohttp
from aiohttp import web
import sys
import importlib.util

def import_scanner(filename):
    spec = importlib.util.spec_from_file_location("scanner", filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

async def handle_tags(request):
    # Return a valid Ollama response to get past detection
    return web.json_response({"models": [{"name": "test-model"}]})

async def handle_ps_malicious(request):
    # Malicious response: 'models' is a list but contains a non-dict item
    return web.json_response({"models": [123]})

async def start_mock_server():
    app = web.Application()
    app.router.add_get('/api/tags', handle_tags)
    app.router.add_get('/api/ps', handle_ps_malicious)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 8083)
    await site.start()
    return runner

async def test_crash(scanner_file):
    print(f"Testing {scanner_file} for crash...")
    scanner_mod = import_scanner(scanner_file)

    # We need to mock the scan. Since we want to test the display logic too,
    # we'll run a scan against our mock server.
    scanner = scanner_mod.OllamaScanner(timeout=2.0)

    # We'll use scan_range which calls scan_single_ip which calls get_process_status_ollama
    # and then main() displays it.
    # Actually, we can just call the methods directly to see the crash.

    async with aiohttp.ClientSession() as session:
        # 1. Detection (should succeed)
        srv_type, models, status = await scanner.detect_server_type('127.0.0.1', 8083, session)
        print(f"Detected: {srv_type}, Models: {models}")

        # 2. Get process status (this should not crash yet, but return bad data)
        processes, status = await scanner.get_process_status_ollama('127.0.0.1', 8083, session)
        print(f"Processes: {processes}")

        # 3. Simulate what happens in main()
        print("Simulating display logic...")
        try:
            for proc in processes[:5]:
                name = proc.get('name', 'unknown')
                size_gb = proc.get('size', 0) / (1024 ** 3)
                print(f"      ├─ {name} (~{size_gb:.1f} GB)")
            print("✅ No crash in display logic.")
        except AttributeError as e:
            print(f"❌ CRASHED in display logic: {e}")
            return True
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return True
    return False

async def main():
    runner = await start_mock_server()

    vulnerable = False
    if await test_crash('Ollama_Scanner_v4.2.py'):
        vulnerable = True

    print("-" * 20)
    if await test_crash('Ollama_Scanner.py'):
        vulnerable = True

    await runner.cleanup()

    if vulnerable:
        print("\nConclusion: VULNERABLE to DoS crash.")
        sys.exit(1)
    else:
        print("\nConclusion: PROTECTED.")
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
