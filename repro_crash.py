import asyncio
import aiohttp
from aiohttp import web
import sys
import os

# Import the scanner logic
import importlib.util

def import_scanner(filename):
    spec = importlib.util.spec_from_file_location("scanner", filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

async def handle_tags(request):
    return web.json_response({
        "models": [{"name": "test-model:latest"}]
    })

async def handle_ps_malformed(request):
    # Malformed: models is a list of strings instead of list of dicts
    return web.json_response({
        "models": ["just-a-string-not-a-dict"]
    })

async def start_mock_server():
    app = web.Application()
    app.router.add_get('/api/tags', handle_tags)
    app.router.add_get('/api/ps', handle_ps_malformed)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 11435)
    await site.start()
    return runner

async def test_vulnerability(scanner_file):
    print(f"\n--- Testing {scanner_file} ---")
    scanner_mod = import_scanner(scanner_file)

    scanner = scanner_mod.OllamaScanner(timeout=2.0)
    async with aiohttp.ClientSession() as session:
        # 1. Detect server type
        print("Detecting server type...")
        srv_type, models, status = await scanner.detect_server_type('127.0.0.1', 11435, session)
        print(f"Server type: {srv_type}, Models: {models}")

        # 2. Simulate what scan_single_ip does during deep scan
        print("Simulating deep scan...")

        processes, ps_status = await scanner.get_process_status_ollama('127.0.0.1', 11435, session)
        print(f"Processes: {processes}")

        # Now simulate the crash point in main() display logic
        print("Attempting to access process list like main() does...")
        try:
            for proc in processes[:5]:
                name = proc.get('name', 'unknown')
                print(f"Process name: {name}")
            print("✅ Handled malformed process list without crash")
            return False
        except Exception as e:
            print(f"❌ CRASHED: {e}")
            return True

async def main():
    runner = await start_mock_server()
    print("Mock server started on 127.0.0.1:11435")

    vulnerable = False
    if await test_vulnerability("Ollama_Scanner.py"):
        vulnerable = True
    if await test_vulnerability("Ollama_Scanner_v4.2.py"):
        vulnerable = True

    await runner.cleanup()

    if vulnerable:
        print("\nConclusion: Scanner is VULNERABLE to malformed JSON (DoS)")
        sys.exit(1)
    else:
        print("\nConclusion: Scanner is PROTECTED")
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
