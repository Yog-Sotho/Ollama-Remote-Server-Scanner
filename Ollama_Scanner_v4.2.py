#!/usr/bin/env python3
"""
Ollama Remote Server Scanner v4.2
Scans IP ranges for open LLM servers (Ollama, LM Studio, TextGen WebUI)
DISCLAIMER: This tool is intended for authorized network administrators only.
Using this tool against networks you do not own may violate local laws.
Always obtain proper authorization before scanning any network.
Version: 4.2.0 - Enterprise Grade (Streaming Optimized)
Last Updated: 2026
Author: Yog-Sotho
"""
import argparse
import asyncio
import json
import re
import sys
import os
from typing import List, Tuple, Optional, Dict, Iterator
from ipaddress import IPv4Network, IPv4Address, AddressValueError, IPv6Network, IPv6Address
import aiohttp
import time
import logging
from collections import defaultdict
from enum import Enum
from dataclasses import dataclass

# Try to import tqdm for progress bars
try:
    import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    logging.warning("tqdm not installed. Using basic progress display.")

# Configure logging with stderr to avoid stdout interference
logger = logging.getLogger(__name__)
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class ScanStatus(Enum):
    """Enumeration for scan status codes"""
    SUCCESS = "success"
    PORT_CLOSED = "port_closed"
    INVALID_RESPONSE = "invalid_response"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    NOT_OLLAMA = "not_ollama"
    NOT_LMSTUDIO = "not_lmstudio"
    NOT_TEXTGEN = "not_textgen"


class ServerType(Enum):
    """Supported LLM server types"""
    OLLAMA = "ollama"
    LM_STUDIO = "lmstudio"
    TEXTGEN_WEBUI = "textgen_webui"
    UNKNOWN = "unknown"


@dataclass
class ScanResult:
    """Structured scan result data"""
    ip: str
    port: int
    server_type: ServerType
    models: List[str]
    process_list: List[Dict]
    model_configs: List[Dict]
    url: str
    is_accessible: bool
    status: ScanStatus


# Regex to match ANSI escape sequences (compiled once at module level for performance)
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def safe_display(text: str, max_len: int = 48) -> str:
    """
    Safely truncate string for logging to prevent leaking full secrets.
    Default max_len of 48 accounts for long IPv6 addresses with ports.
    """
    if len(text) <= max_len:
        return text
    # Show only the first 8 characters of very long strings to protect potential secrets
    return f"{text[:8]}...[truncated, len={len(text)}]"


def sanitize_text(text: str) -> str:
    """
    Remove ANSI escape sequences and non-printable control characters
    to prevent terminal injection attacks from remote server data.
    """
    if not isinstance(text, str):
        return text
    # Remove ANSI escape sequences
    text = ANSI_ESCAPE.sub('', text)
    # Remove non-printable control characters except common safe whitespace (\n, \t)
    # Note: \r is excluded to prevent line-overwrite deception in terminals
    return "".join(ch for ch in text if ch.isprintable() or ch in "\n\t")


def format_target_url(ip: str, port: int) -> str:
    """Safely construct URL string handling both IPv4 and IPv6 formats."""
    try:
        addr = IPv6Address(ip)
        return f"http://[{addr}]:{port}"
    except AddressValueError:
        pass
    return f"http://{ip}:{port}"


def validate_ip_range_static(ip_range: str) -> Iterator[Tuple[str, str]]:
    """
    Validate and expand a single IP range into individual IPs
    
    Static method - does not require scanner instance.
    Returns: Iterator of tuples (ip_string, ip_version)
    """
    if not ip_range.strip():
        raise ValueError("Empty IP range provided")

    # Security: Truncate display string to prevent potential leak of full secrets if mis-parsed
    ip_display = safe_display(ip_range)
        
    # Try CIDR notation first (both IPv4 and IPv6)
    try:
        network = IPv4Network(ip_range, strict=False)
        # Use built-in is_private which covers 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.
        if not (network.is_private or network.is_loopback):
        if not network.is_private:
            logger.warning(f"⚠️  Scanning PUBLIC IPv4 range: {ip_display}. Ensure you have permission!")
        for ip in network:
            yield (str(ip), 'IPv4')
        return
    except ValueError:
        pass
        
    try:
        network = IPv6Network(ip_range, strict=False)
        if not network.is_private:
            logger.warning(f"⚠️  Scanning PUBLIC IPv6 range: {ip_display}. Ensure you have permission!")
        for ip in network:
            yield (str(ip), 'IPv6')
        return
    except ValueError:
        pass
    
    # Try IPv4 range notation like "192.168.1.1-10"
    if '-' in ip_range:
        parts = ip_range.split('-')
        if len(parts) != 2:
            raise ValueError(f"Invalid range format: {ip_display}")
        start_ip_str, end_part = parts[0].strip(), parts[1].strip()
        
        try:
            start_ip = IPv4Address(start_ip_str)
        except AddressValueError:
            raise ValueError(f"Invalid start IP: {safe_display(start_ip_str)}")
            
        if '.' in end_part:
            try:
                end_ip = IPv4Address(end_part)
            except AddressValueError:
                raise ValueError(f"Invalid end IP: {safe_display(end_part)}")
            start_int = int(start_ip)
            end_int = int(end_ip)
            if start_int > end_int:
                raise ValueError("Start IP cannot be greater than end IP")
            for i in range(start_int, end_int + 1):
                yield (str(IPv4Address(i)), 'IPv4')
            return
        else:
            try:
                end_suffix = int(end_part)
            except ValueError:
                raise ValueError(f"Invalid end suffix: {safe_display(end_part)}")
            base_parts = start_ip_str.split('.')
            start_num = int(base_parts[-1])
            base = '.'.join(base_parts[:-1])
            if end_suffix < start_num:
                raise ValueError("End suffix cannot be less than start suffix")
            for i in range(start_num, end_suffix + 1):
                ip_candidate = f"{base}.{i}"
                try:
                    IPv4Address(ip_candidate)
                    yield (ip_candidate, 'IPv4')
                except AddressValueError:
                    continue
            return
            
    # Single IP (try IPv4 first)
    try:
        IPv4Address(ip_range.strip())
        yield (ip_range.strip(), 'IPv4')
        return
    except AddressValueError:
        pass
        
    try:
        IPv6Address(ip_range.strip())
        yield (ip_range.strip(), 'IPv6')
        return
    except AddressValueError:
        pass
        
    raise ValueError(f"Invalid IP address or range: {ip_display}")


def count_ips_in_range_static(ip_range: str) -> int:
    """
    Mathematically calculate the number of IPs in a range or CIDR without expansion.
    O(1) complexity for most formats.
    """
    if not ip_range.strip():
        return 0

    # Try CIDR notation
    try:
        network = IPv4Network(ip_range.strip(), strict=False)
        return network.num_addresses
    except ValueError:
        pass

    try:
        network = IPv6Network(ip_range.strip(), strict=False)
        return network.num_addresses
    except ValueError:
        pass

    # Try IPv4 range notation like "192.168.1.1-10"
    if '-' in ip_range:
        parts = ip_range.split('-')
        if len(parts) == 2:
            start_ip_str, end_part = parts[0].strip(), parts[1].strip()
            try:
                start_ip = IPv4Address(start_ip_str)
                if '.' in end_part:
                    end_ip = IPv4Address(end_part)
                    diff = int(end_ip) - int(start_ip)
                    return max(0, diff + 1) if diff >= 0 else 0
                else:
                    end_suffix = int(end_part)
                    base_parts = start_ip_str.split('.')
                    start_num = int(base_parts[-1])
                    diff = end_suffix - start_num
                    return max(0, diff + 1) if diff >= 0 else 0
            except (AddressValueError, ValueError):
                pass

    # Single IP
    try:
        IPv4Address(ip_range.strip())
        return 1
    except AddressValueError:
        pass

    try:
        IPv6Address(ip_range.strip())
        return 1
    except AddressValueError:
        pass

    return 0


def parse_ip_from_input(input_source: str, is_file: bool = False) -> Iterator[Tuple[str, str]]:
    """
    Parse IP addresses/ranges from file or command-line input
    
    Streamed approach - yields IPs one by one to reduce memory usage
    
    Args:
        input_source: File path or single range string
        is_file: Whether input_source is a file path
        
    Yields:
        Tuples of (ip_string, ip_version)
    """
    if is_file:
        if not os.path.exists(input_source):
            raise FileNotFoundError(f"Input file not found: {input_source}")
        
        logger.info(f"Reading IP ranges from file: {input_source}")
        with open(input_source, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Security: Truncate logging to prevent sensitive data leakage
                line_display = safe_display(line)
                try:
                    count = 0
                    for ip in validate_ip_range_static(line):
                        yield ip
                        count += 1
                    logger.debug(f"Line {line_num}: '{line_display}' -> {count} IPs")
                except ValueError as e:
                    logger.warning(f"Skipping invalid line {line_num} ('{line_display}'): {e}")
    else:
        # Single range from command line
        yield from validate_ip_range_static(input_source)


class OllamaScanner:
    """Professional-grade LLM server scanner with enterprise enhancements"""
    
    def __init__(
        self,
        timeout: float = 5.0,
        max_concurrent: int = 100,
        retry_attempts: int = 3,
        retry_delay: float = 0.5,
        enable_dns_cache: bool = True,
        disable_ssl_verify: bool = False,
        port_timeout: float = None
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        self.enable_dns_cache = enable_dns_cache
        self.disable_ssl_verify = disable_ssl_verify
        self.port_timeout = port_timeout if port_timeout is not None else timeout / 2
        self.semaphore = asyncio.Semaphore(max_concurrent)
        # FIX 4.1: Removed unused dns_cache dictionary (TTL handled by TCPConnector)
        self.stats: Dict[str, int] = defaultdict(int)
        
    async def check_port(self, ip: str, port: int) -> Tuple[bool, ScanStatus]:
        """
        Check if a specific port is open on an IP address
        
        Uses asyncio.wait_for with configurable timeout
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.port_timeout
            )
            writer.close()
            await writer.wait_closed()
            return (True, ScanStatus.SUCCESS)
        except asyncio.TimeoutError:
            self.stats["timeout"] += 1
            return (False, ScanStatus.TIMEOUT)
        except ConnectionRefusedError:
            self.stats["port_closed"] += 1
            return (False, ScanStatus.PORT_CLOSED)
        except OSError as e:
            self.stats["connection_error"] += 1
            logger.debug(f"OS error checking port {ip}:{port}: {e}")
            return (False, ScanStatus.CONNECTION_ERROR)
        except Exception as e:
            self.stats["connection_error"] += 1
            logger.debug(f"Unexpected error checking port {ip}:{port}: {e}")
            return (False, ScanStatus.CONNECTION_ERROR)
            
    async def detect_server_type(
        self,
        ip: str,
        port: int,
        session: aiohttp.ClientSession
    ) -> Tuple[ServerType, Optional[List[str]], ScanStatus]:
        """
        Detect which type of LLM server is running at the target
        
        Supports:
        - Ollama (/api/tags)
        - LM Studio (/v1/models)
        - TextGen WebUI (/api/info)
        
        Semaphore acquired per-request, not held across all probes
        Per-endpoint retry logic
        """
        url_tags = f"{format_target_url(ip, port)}/api/tags"
        url_models = f"{format_target_url(ip, port)}/v1/models"
        url_info = f"{format_target_url(ip, port)}/api/info"
        headers = {'User-Agent': 'LLMScanner/4.2'}
        ssl_setting = not self.disable_ssl_verify
        
        ollama_attempts = 0
        lmstudio_attempts = 0
        textgen_attempts = 0
        
        # Try Ollama first (most common)
        while ollama_attempts < self.retry_attempts:
            try:
                async with self.semaphore:
                    async with session.get(
                        url_tags,
                        headers=headers,
                        ssl=ssl_setting,
                        timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2),
                        allow_redirects=False
                    ) as response:
                        if response.status == 200:
                            try:
                                data = await response.json()
                                if 'models' in data:
                                    models = [sanitize_text(model.get('name', 'unknown')) for model in data['models']]
                                    self.stats["successful_queries"] += 1
                                    self.stats[ServerType.OLLAMA.value + "_count"] += 1
                                    return (ServerType.OLLAMA, models, ScanStatus.SUCCESS)
                            except aiohttp.ContentTypeError:
                                pass
                        break
                    
            except asyncio.TimeoutError:
                ollama_attempts += 1
                if ollama_attempts >= self.retry_attempts:
                    self.stats["timeout"] += 1
                    break
                wait_time = self.retry_delay * (2 ** ollama_attempts)
                await asyncio.sleep(wait_time)
                
            except Exception as e:
                ollama_attempts += 1
                if ollama_attempts >= self.retry_attempts:
                    self.stats["connection_error"] += 1
                    break
                wait_time = self.retry_delay * (2 ** ollama_attempts)
                await asyncio.sleep(wait_time)
        
        # Try LM Studio
        while lmstudio_attempts < self.retry_attempts:
            try:
                async with self.semaphore:
                    async with session.get(
                        url_models,
                        headers=headers,
                        ssl=ssl_setting,
                        timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2),
                        allow_redirects=False
                    ) as response:
                        if response.status == 200:
                            try:
                                data = await response.json()
                                if 'data' in data:
                                    models = [sanitize_text(m.get('id', m.get('name', 'unknown'))) for m in data['data']]
                                    self.stats[ServerType.LM_STUDIO.value + "_count"] += 1
                                    return (ServerType.LM_STUDIO, models, ScanStatus.SUCCESS)
                            except aiohttp.ContentTypeError:
                                pass
                        break
                    
            except asyncio.TimeoutError:
                lmstudio_attempts += 1
                if lmstudio_attempts >= self.retry_attempts:
                    break
                wait_time = self.retry_delay * (2 ** lmstudio_attempts)
                await asyncio.sleep(wait_time)
                
            except Exception as e:
                lmstudio_attempts += 1
                if lmstudio_attempts >= self.retry_attempts:
                    break
                wait_time = self.retry_delay * (2 ** lmstudio_attempts)
                await asyncio.sleep(wait_time)
        
        # Try TextGen WebUI
        while textgen_attempts < self.retry_attempts:
            try:
                async with self.semaphore:
                    async with session.get(
                        url_info,
                        headers=headers,
                        ssl=ssl_setting,
                        timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2),
                        allow_redirects=False
                    ) as response:
                        if response.status == 200:
                            try:
                                data = await response.json()
                                models = [sanitize_text(data.get('loading_model', data.get('model_name', 'unknown')))]
                                self.stats[ServerType.TEXTGEN_WEBUI.value + "_count"] += 1
                                return (ServerType.TEXTGEN_WEBUI, models, ScanStatus.SUCCESS)
                            except aiohttp.ContentTypeError:
                                pass
                        break
                        
            except asyncio.TimeoutError:
                textgen_attempts += 1
                if textgen_attempts >= self.retry_attempts:
                    break
                wait_time = self.retry_delay * (2 ** textgen_attempts)
                await asyncio.sleep(wait_time)
                
            except Exception as e:
                textgen_attempts += 1
                if textgen_attempts >= self.retry_attempts:
                    break
                wait_time = self.retry_delay * (2 ** textgen_attempts)
                await asyncio.sleep(wait_time)
        
        return (ServerType.UNKNOWN, [], ScanStatus.NOT_OLLAMA)
        
    async def get_process_status_ollama(
        self,
        ip: str,
        port: int,
        session: aiohttp.ClientSession
    ) -> Tuple[Optional[List[Dict]], ScanStatus]:
        """Get currently loaded models from Ollama server (/api/ps) with retry logic"""
        url = f"http://{ip}:{port}/api/ps"
        headers = {'User-Agent': 'LLMScanner/4.2', 'Accept': 'application/json'}
        ssl_setting = not self.disable_ssl_verify
        
        for attempt in range(self.retry_attempts):
            try:
                async with session.get(
                    url,
                    headers=headers,
                    ssl=ssl_setting,
                    timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2),
                    allow_redirects=False
                ) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            processes = data.get('models', [])
                            # Sanitize process names to prevent terminal injection
                            for proc in processes:
                                if 'name' in proc:
                                    proc['name'] = sanitize_text(proc['name'])
                            self.stats["process_status_success"] += 1
                            return (processes, ScanStatus.SUCCESS)
                        except aiohttp.ContentTypeError:
                            return ([], ScanStatus.INVALID_RESPONSE)
                    elif response.status == 404:
                        return ([], ScanStatus.SUCCESS)
                    else:
                        return (None, ScanStatus.INVALID_RESPONSE)
                        
            except asyncio.TimeoutError:
                if attempt < self.retry_attempts - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    await asyncio.sleep(wait_time)
                    continue
                return ([], ScanStatus.TIMEOUT)
            except Exception as e:
                logger.debug(f"Error getting process status from {ip}:{port}: {e}")
                if attempt < self.retry_attempts - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    await asyncio.sleep(wait_time)
                    continue
                return ([], ScanStatus.CONNECTION_ERROR)
        
        return ([], ScanStatus.CONNECTION_ERROR)
            
    async def get_model_info_ollama(
        self,
        ip: str,
        port: int,
        session: aiohttp.ClientSession,
        model_name: str
    ) -> Tuple[Optional[Dict], ScanStatus]:
        """Get model configuration details from Ollama server (/api/show) with retry logic"""
        url = f"http://{ip}:{port}/api/show"
        headers = {
            'User-Agent': 'LLMScanner/4.2',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        payload = {"name": model_name}
        ssl_setting = not self.disable_ssl_verify
        
        for attempt in range(self.retry_attempts):
            try:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    ssl=ssl_setting,
                    timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2),
                    allow_redirects=False
                ) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            config = {
                                "system_prompt": sanitize_text(data.get("system", "")),
                                "parameters": sanitize_text(data.get("parameters", "")),
                                "template": sanitize_text(data.get("template", ""))
                            }
                            self.stats["model_info_success"] += 1
                            return (config, ScanStatus.SUCCESS)
                        except aiohttp.ContentTypeError:
                            return (None, ScanStatus.INVALID_RESPONSE)
                    elif response.status == 404:
                        return ({}, ScanStatus.SUCCESS)
                    else:
                        return (None, ScanStatus.INVALID_RESPONSE)
                        
            except asyncio.TimeoutError:
                if attempt < self.retry_attempts - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    await asyncio.sleep(wait_time)
                    continue
                return (None, ScanStatus.TIMEOUT)
            except Exception as e:
                logger.debug(f"Error getting model info for {model_name} from {ip}:{port}: {e}")
                if attempt < self.retry_attempts - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    await asyncio.sleep(wait_time)
                    continue
                return (None, ScanStatus.CONNECTION_ERROR)
        
        return (None, ScanStatus.CONNECTION_ERROR)
        
    async def scan_single_ip(
        self,
        ip: str,
        ip_version: str,
        port: int,
        session: aiohttp.ClientSession,
        deep_scan: bool = False
    ) -> Optional[ScanResult]:
        """Scan a single IP for LLM servers"""
        try:
            is_open, port_status = await self.check_port(ip, port)
            if not is_open:
                return None
                
            url = format_target_url(ip, port)
            
            server_type, models, model_status = await self.detect_server_type(ip, port, session)
            
            process_list = []
            model_configs = []
            
            if deep_scan and models is not None and len(models) > 0 and server_type == ServerType.OLLAMA:
                process_list, ps_status = await self.get_process_status_ollama(ip, port, session)
                
                for model_name in models[:3]:
                    config, info_status = await self.get_model_info_ollama(ip, port, session, model_name)
                    if config:
                        model_configs.append({
                            "model_name": model_name,
                            "config": config
                        })
            
            return ScanResult(
                ip=ip,
                port=port,
                server_type=server_type,
                models=models if models else [],
                process_list=process_list if process_list else [],
                model_configs=model_configs if model_configs else [],
                url=url,
                is_accessible=models is not None,
                status=model_status
            )
            
        except Exception as e:
            logger.debug(f"Unexpected error scanning {ip}:{port}: {e}")
            self.stats["scan_errors"] += 1
            return None
            
    def _count_ips_without_exhausting(self, input_source: str, is_file: bool = False) -> int:
        """
        Count total IPs without consuming the iterator
        
        For CIDR ranges, compute directly from network size
        For files, parse each line and sum counts
        """
        total = 0
        if is_file:
            with open(input_source, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        total += count_ips_in_range_static(line)
        else:
            total = count_ips_in_range_static(input_source)
        return total
        
    async def scan_range(
        self,
        input_source: str,
        is_file: bool = False,
        port: int = 11434,
        deep_scan: bool = False,
        show_progress: bool = True,
        batch_size: int = 1000
    ) -> List[ScanResult]:
        """
        Main scanning coroutine with improved resource management
        
        FIX 5.1-5.2: Processes IPs in batches without loading all into memory
        
        Args:
            input_source: IP range string or file path
            is_file: Whether input_source is a file
            port: Port to scan
            deep_scan: Enable extended API queries
            show_progress: Display progress indicator
            batch_size: Number of IPs per batch for memory optimization
            
        Returns:
            List of ScanResult objects
        """
        # Count total IPs without exhausting iterator
        total_ips = self._count_ips_without_exhausting(input_source, is_file)
        
        print(f"🔍 Scanning {total_ips} IPs for port {port}..." + (" [DEEP SCAN]" if deep_scan else ""))
        print("-" * 70, file=sys.stderr)
        
        if total_ips > 10000:
            confirm = input(f"\n⚠️  Warning: Scanning {total_ips} IPs may take significant time.\nContinue? (y/N): ").lower()
            if confirm != 'y':
                print("❌ Scan cancelled by user.", file=sys.stderr)
                return []
                
        results: List[ScanResult] = []
        start_time = time.time()
        completed = 0
        successes = 0
        
        # Optimization: Match pool size to concurrency to prevent bottlenecking
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent + 50,
            limit_per_host=20,
            ttl_dns_cache=300 if self.enable_dns_cache else None
        )
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2)
        
        if HAS_TQDM and show_progress:
            progress_bar = tqdm.tqdm(total=total_ips, desc="Scanning", unit="IP", file=sys.stdout)
        else:
            progress_bar = None
            
        # FIX 6.1: Removed unused import math
        
        async with aiohttp.ClientSession(
            timeout=timeout_obj,
            connector=connector,
            headers={'Accept': 'application/json'}
        ) as session:
            ip_iterator = parse_ip_from_input(input_source, is_file=is_file)
            active_tasks = set()

            async def handle_completed(tasks):
                nonlocal successes, completed
                for task in tasks:
                    try:
                        result = await task
                        completed += 1
                        if result:
                            successes += 1
                            if result.is_accessible and result.models:
                                results.append(result)
                                if HAS_TQDM and show_progress:
                                    tqdm.write(f"\n✅ {result.server_type.value.upper()} Server: {result.url}")
                                    tqdm.write(f"   Models ({len(result.models)}): {', '.join(result.models[:5])}"
                                               f"{'...' if len(result.models) > 5 else ''}")
                                    models_str = ', '.join(result.models[:5])
                                    suffix = '...' if len(result.models) > 5 else ''
                                    tqdm.write(f"   Models ({len(result.models)}): {models_str}{suffix}")
                                    
                                    if deep_scan and result.process_list:
                                        tqdm.write(f"   🔄 Loaded: {len(result.process_list)} model(s) in RAM/VRAM")
                                else:
                                    print(f"\n✅ {result.server_type.value.upper()} Server: {result.url}", flush=True)
                                    models_str = ', '.join(result.models[:5])
                                    suffix = '...' if len(result.models) > 5 else ''
                                    print(f"   Models ({len(result.models)}): {models_str}{suffix}", flush=True)
                                        
                                    if deep_scan and result.process_list:
                                        print(f"   🔄 Loaded: {len(result.process_list)} model(s) in RAM/VRAM", flush=True)
                            elif result.is_accessible:
                                results.append(result)
                                if HAS_TQDM and show_progress:
                                    tqdm.write(f"✓ Open port at {result.url} - No models returned")
                                else:
                                    print(f"✓ Open port at {result.url} - No models returned", flush=True)
                            else:
                                if HAS_TQDM and show_progress:
                                    tqdm.write(f"❌ Invalid server at {result.url}")
                                else:
                                    print(f"❌ Invalid server at {result.url}", flush=True)

                        if progress_bar:
                            progress_bar.update(1)
                        elif show_progress and (completed % 50 == 0 or completed == total_ips):
                            elapsed = time.time() - start_time
                            rate = completed / elapsed if elapsed > 0 else 0
                            percent = (completed / total_ips) * 100 if total_ips > 0 else 0
                            print(f"\r📈 Progress: {completed}/{total_ips} ({percent:.1f}%) | "
                                  f"Rate: {rate:.1f} IPs/sec | Successes: {successes}",
                                  end='', flush=True, file=sys.stderr)
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        logger.error(f"Error processing task: {e}")

            for ip, version in ip_iterator:
                if len(active_tasks) >= self.max_concurrent:
                    done, active_tasks = await asyncio.wait(active_tasks, return_when=asyncio.FIRST_COMPLETED)
                    await handle_completed(done)

                task = asyncio.create_task(self.scan_single_ip(ip, version, port, session, deep_scan))
                active_tasks.add(task)

            if active_tasks:
                done, pending = await asyncio.wait(active_tasks)
                await handle_completed(done)
        
        if progress_bar:
            progress_bar.close()
        
        duration = time.time() - start_time
        print(f"\n\n🏁 Scan completed in {duration:.2f} seconds", file=sys.stderr)
        
        print("\n📊 Scan Statistics:", file=sys.stderr)
        print(f"  • Total IPs scanned:     {total_ips}", file=sys.stderr)
        print(f"  • Successful queries:    {self.stats.get('successful_queries', 0)}", file=sys.stderr)
        print(f"  • Port closed:           {self.stats.get('port_closed', 0)}", file=sys.stderr)
        print(f"  • Timeouts:              {self.stats.get('timeout', 0)}", file=sys.stderr)
        print(f"  • Connection errors:     {self.stats.get('connection_error', 0)}", file=sys.stderr)
        print(f"  • Not detected:          {self.stats.get('not_ollama', 0)}", file=sys.stderr)
        if deep_scan:
            print(f"  • Process status checks: {self.stats.get('process_status_success', 0)}", file=sys.stderr)
            print(f"  • Model info retrieved:  {self.stats.get('model_info_success', 0)}", file=sys.stderr)
        
        print(f"\n📋 Discovered Server Types:", file=sys.stderr)
        print(f"  • Ollama:         {self.stats.get('ollama_count', 0)}", file=sys.stderr)
        print(f"  • LM Studio:      {self.stats.get('lmstudio_count', 0)}", file=sys.stderr)
        print(f"  • TextGen WebUI:  {self.stats.get('textgen_webui_count', 0)}", file=sys.stderr)
        
        if total_ips > 0:
            print(f"  • Overall success rate:  {(successes / total_ips * 100):.2f}%", file=sys.stderr)
        else:
            print(f"  • Overall success rate:  N/A (No IPs)", file=sys.stderr)
            
        return results
        
    def generate_report(
        self,
        results: List[ScanResult],
        output_path: str,
        format_type: str = 'json'
    ) -> str:
        """Generate scan report in specified format"""
        timestamp = time.strftime("%Y-%m-%d_%H%M%S", time.gmtime())
        
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            
        if format_type == 'json':
            report_path = f"{output_path}_report_{timestamp}.json"
            report_data = {
                "scan_summary": {
                    "timestamp": timestamp,
                    "total_found": len(results),
                    "statistics": dict(self.stats)
                },
                "servers": [
                    {
                        "ip": r.ip,
                        "port": r.port,
                        "url": r.url,
                        "server_type": r.server_type.value,
                        "models_count": len(r.models),
                        "models": r.models,
                        "process_status": r.process_list,
                        "model_configs": r.model_configs,
                        "is_accessible": r.is_accessible,
                        "status": r.status.value
                    }
                    for r in results
                ]
            }
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
                
        elif format_type == 'text':
            report_path = f"{output_path}_report_{timestamp}.txt"
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("LLM Server Scan Report\n")
                f.write("=" * 60 + "\n")
                f.write(f"Generated: {timestamp}\n")
                f.write(f"Total Servers Found: {len(results)}\n\n")
                f.write("Statistics:\n")
                for metric, count in self.stats.items():
                    f.write(f"  {metric}: {count}\n")
                f.write("\n\nDiscovered Servers:\n")
                f.write("-" * 60 + "\n")
                for r in results:
                    f.write(f"\n[{r.server_type.value}] {r.url}\n")
                    if r.models:
                        f.write(f"  Models: {', '.join(r.models)}\n")
                    if r.process_list:
                        f.write(f"  Loaded Processes: {len(r.process_list)}\n")
                        
        else:
            raise ValueError(f"Unsupported format type: {format_type}")
            
        return report_path


def main():
    parser = argparse.ArgumentParser(
        description="Scan IP ranges for open LLM servers (Ollama, LM Studio, TextGen WebUI)",
        epilog="""
EXAMPLES:
  python Ollama_scanner_v4.2.py 192.168.1.0/24                      # Basic CIDR scan
  python Ollama_scanner_v4.2.py 192.168.1.1-100                     # Range notation
  python Ollama_scanner_v4.2.py --file targets.txt                  # Read from file
  python Ollama_scanner_v4.2.py 192.168.1.0/24 --deep               # Deep API scan
  python Ollama_scanner_v4.2.py 192.168.1.0/24 -p 1234              # Custom port (LM Studio)
  
DISCLAIMER: Only scan networks you own or have explicit permission to test.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("range", nargs="?", help="IP range to scan (CIDR notation, e.g., 192.168.1.0/24)")
    parser.add_argument("-f", "--file", help="File containing IP addresses/ranges (one per line)")
    parser.add_argument("-p", "--port", type=int, default=11434, help="Port to scan (default: 11434 Ollama)")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Connection timeout in seconds (default: 5)")
    parser.add_argument("-c", "--concurrent", type=int, default=100, help="Max concurrent connections (default: 100)")
    parser.add_argument("-r", "--retries", type=int, default=3, help="Retry attempts per target (default: 3)")
    parser.add_argument("-d", "--retry-delay", type=float, default=0.5, help="Base delay between retries (default: 0.5)")
    parser.add_argument("-o", "--output", help="Base name for output files")
    parser.add_argument("--deep", action="store_true", help="Perform deep API scan (/api/ps, /api/show)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    parser.add_argument("--disable-dns-cache", action="store_true", help="Disable DNS caching")
    parser.add_argument("--no-progress", action="store_true", help="Suppress progress display")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--batch-size", type=int, default=1000, help="Batch size for memory optimization (default: 1000)")
    
    args = parser.parse_args()
    
    if not args.range and not args.file:
        parser.print_help()
        print("\n❌ Error: You must provide either an IP range or --file argument", file=sys.stderr)
        sys.exit(1)
        
    if args.port < 1 or args.port > 65535:
        print("❌ Error: Port must be between 1 and 65535", file=sys.stderr)
        sys.exit(1)
        
    if args.timeout <= 0:
        print("❌ Error: Timeout must be positive", file=sys.stderr)
        sys.exit(1)
    if args.concurrent <= 0:
        print("❌ Error: Concurrent connections must be positive", file=sys.stderr)
        sys.exit(1)
    if args.retries < 0:
        print("❌ Error: Retry attempts cannot be negative", file=sys.stderr)
        sys.exit(1)
    if args.retry_delay < 0:
        print("❌ Error: Retry delay cannot be negative", file=sys.stderr)
        sys.exit(1)
        
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose/debug mode enabled")
    
    print("=" * 70, file=sys.stderr)
    print("🔍 LLM SERVER SCANNER v4.2 - ENTERPRISE GRADE", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print("This tool is for authorized security testing only.", file=sys.stderr)
    print("Ensure you have explicit permission to scan the target network.", file=sys.stderr)
    print("Unauthorized scanning may violate local laws and regulations.", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    
    if args.file:
        print(f"📄 Input Source: {args.file}", file=sys.stderr)
    else:
        print(f"🎯 Target Range: {args.range}", file=sys.stderr)
    print(f"🔌 Port: {args.port}", file=sys.stderr)
    print(f"⚡ Concurrency: {args.concurrent}", file=sys.stderr)
    print(f"⏱️  Timeout: {args.timeout}s | Retries: {args.retries}", file=sys.stderr)
    print(f"Mode: {'DEEP SCAN' if args.deep else 'BASIC SCAN'}", file=sys.stderr)
    print("-" * 70, file=sys.stderr)
    
    scanner = OllamaScanner(
        timeout=args.timeout,
        max_concurrent=args.concurrent,
        retry_attempts=args.retries,
        retry_delay=args.retry_delay,
        enable_dns_cache=not args.disable_dns_cache,
        disable_ssl_verify=args.no_ssl_verify,
        port_timeout=args.timeout / 2
    )
    
    try:
        input_source = args.file if args.file else args.range
        is_file = bool(args.file)
    except Exception as e:
        print(f"\n❌ Error parsing input: {e}", file=sys.stderr)
        sys.exit(1)
        
    scan_start_time = time.time()
    
    try:
        results = asyncio.run(scanner.scan_range(
            input_source,
            is_file=is_file,
            port=args.port,
            deep_scan=args.deep,
            show_progress=not args.no_progress,
            batch_size=args.batch_size
        ))
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user (Ctrl+C)", file=sys.stderr)
        sys.exit(130)
        
    except Exception as e:
        print(f"\n❌ Fatal error during scan: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    duration = time.time() - scan_start_time
    
    accessible_servers = []
    print(f"\n{'='*70}", file=sys.stderr)
    print(f"📊 RESULTS SUMMARY - {len(results)} servers discovered", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    
    for idx, result in enumerate(results, 1):
        # FIX 6.3: Consistent flush=True throughout
        print(f"\n{idx}. {result.url}", flush=True)
        print(f"   ✓ Status: ACCESSIBLE", flush=True)
        print(f"   🔧 Server Type: {result.server_type.value.upper()}", flush=True)
        print(f"   📦 Models: {len(result.models)} total", flush=True)
        print(f"   📝 List: {', '.join(result.models[:10])}", flush=True)
        if len(result.models) > 10:
            print(f"         ... and {len(result.models) - 10} more", flush=True)
            
        if args.deep:
            if result.process_list:
                print(f"\n   🔄 LOADED IN RAM/VRAM:", flush=True)
                for proc in result.process_list[:5]:
                    name = proc.get('name', 'unknown')
                    size_gb = proc.get('size', 0) / (1024**3)
                    print(f"      ├─ {name} (~{size_gb:.1f} GB)", flush=True)
                if len(result.process_list) > 5:
                    print(f"      └─ ... and {len(result.process_list) - 5} more", flush=True)
                    
            if result.model_configs:
                print(f"\n   ⚙️  MODEL CONFIGURATIONS:", flush=True)
                for mc in result.model_configs[:3]:
                    name = mc.get('model_name', 'unknown')
                    config = mc.get('config', {})
                    system = config.get('system_prompt', '')
                    params = config.get('parameters', '')
                    print(f"      ├─ {name}", flush=True)
                    if system:
                        preview = system[:60].replace('\n', ' ')
                        print(f"      │   System: {preview}..." if len(system) > 60 else f"      │   System: {preview}", flush=True)
                    if params:
                        print(f"      │   Params: {params[:50] if len(params) > 50 else params}", flush=True)
                if len(result.model_configs) > 3:
                    print(f"      └─ ... and {len(result.model_configs) - 3} more", flush=True)
                    
        accessible_servers.append({
            'ip': result.ip,
            'models': result.models,
            'server_type': result.server_type,
            'status': result.status
        })
    
    if args.output:
        try:
            report_path = scanner.generate_report(results, args.output, 'json')
            print(f"\n💾 JSON Report saved: {report_path}", file=sys.stderr)
        except Exception as e:
            print(f"❌ Error generating JSON report: {e}", file=sys.stderr)
            
        text_path = f"{args.output}.txt"
        with open(text_path, 'w', encoding='utf-8') as f:
            for r in results:
                f.write(f"{r.url}\n")
        print(f"💾 Server list exported to {text_path}", file=sys.stderr)
    
    print("\n" + "=" * 70, file=sys.stderr)
    print("✅ SCAN COMPLETE", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"Duration: {duration:.2f} seconds", file=sys.stderr)
    print(f"Servers Found: {len(accessible_servers)}", file=sys.stderr)
    safe_rate = len(results) / duration if duration > 0 else 0
    print(f"Scan Rate: {safe_rate:.2f} IPs/sec", file=sys.stderr)
    print("=" * 70, file=sys.stderr)


if __name__ == "__main__":
    main()
