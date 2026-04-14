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

async def handle_redirect(request):
    return web.Response(status=302, headers={"Location": "http://127.0.0.1:8082/api/tags"})

async def handle_ollama(request):
    return web.json_response({"models": [{"name": "mock-model:latest"}]})

async def start_mock_servers():
    # Redirect server
    app_redirect = web.Application()
    app_redirect.router.add_get('/api/tags', handle_redirect)
    runner_redirect = web.AppRunner(app_redirect)
    await runner_redirect.setup()
    site_redirect = web.TCPSite(runner_redirect, '127.0.0.1', 8081)
    await site_redirect.start()

    # Target server
    app_ollama = web.Application()
    app_ollama.router.add_get('/api/tags', handle_ollama)
    runner_ollama = web.AppRunner(app_ollama)
    await runner_ollama.setup()
    site_ollama = web.TCPSite(runner_ollama, '127.0.0.1', 8082)
    await site_ollama.start()

    return runner_redirect, runner_ollama

async def test_ssrf(scanner_file):
    print(f"\nTesting {scanner_file} for SSRF (following redirects)...")
    scanner_mod = import_scanner(scanner_file)

    async with aiohttp.ClientSession() as session:
        scanner = scanner_mod.OllamaScanner(timeout=2.0)
        # We try to detect server type on the redirecting port
        server_type, models, status = await scanner.detect_server_type('127.0.0.1', 8081, session)

        if server_type == scanner_mod.ServerType.OLLAMA:
            print(f"❌ VULNERABLE: {scanner_file} followed the redirect!")
            return True
        else:
            print(f"✅ PROTECTED: {scanner_file} did not follow the redirect.")
            return False

async def main():
    runner_redirect, runner_ollama = await start_mock_servers()

    vulnerable = False
    if await test_ssrf('Ollama_Scanner.py'):
        vulnerable = True
    if await test_ssrf('Ollama_Scanner_v4.2.py'):
        vulnerable = True

    await runner_redirect.cleanup()
    await runner_ollama.cleanup()

    if vulnerable:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
