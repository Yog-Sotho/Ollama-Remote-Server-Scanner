#!/usr/bin/env python3
"""
Ollama Remote Server Scanner v4.2
Scans IP ranges for open LLM servers (Ollama, LM Studio, TextGen WebUI
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
import sys
import os
from typing import List, Tuple, Optional, Dict, Any, Iterator, AsyncIterator
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
    UNDETECTED = "undetected"


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
        
    # Try CIDR notation first (both IPv4 and IPv6)
    try:
        network = IPv4Network(ip_range, strict=False)
        private_check = any([
            network.subnet_of(IPv4Network('10.0.0.0/8')),
            network.subnet_of(IPv4Network('172.16.0.0/12')),
            network.subnet_of(IPv4Network('192.168.0.0/16'))
        ])
        if not private_check:
            logger.warning(f"⚠️  Scanning PUBLIC IPv4 range: {ip_range}. Ensure you have permission!")
        yield from ((str(ip), 'IPv4') for ip in network)
        return
    except ValueError:
        pass
        
    try:
        network = IPv6Network(ip_range, strict=False)
        is_private = network.subnet_of(IPv6Network('fc00::/7'))
        if not is_private:
            logger.warning(f"⚠️  Scanning PUBLIC IPv6 range: {ip_range}. Ensure you have permission!")
        yield from ((str(ip), 'IPv6') for ip in network)
        return
    except ValueError:
        pass
    
    # Try IPv4 range notation like "192.168.1.1-10"
    if '-' in ip_range:
        parts = ip_range.split('-')
        if len(parts) != 2:
            raise ValueError(f"Invalid range format: {ip_range}")
        start_ip_str, end_part = parts[0].strip(), parts[1].strip()
        
        try:
            start_ip = IPv4Address(start_ip_str)
        except AddressValueError:
            raise ValueError(f"Invalid start IP: {start_ip_str}")
            
        if '.' in end_part:
            try:
                end_ip = IPv4Address(end_part)
            except AddressValueError:
                raise ValueError(f"Invalid end IP: {end_part}")
            start_int = int(start_ip)
            end_int = int(end_ip)
            if start_int > end_int:
                raise ValueError("Start IP cannot be greater than end IP")
            yield from ((str(IPv4Address(i)), 'IPv4') for i in range(start_int, end_int + 1))
            return
        else:
            try:
                end_suffix = int(end_part)
            except ValueError:
                raise ValueError(f"Invalid end suffix: {end_part}")
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
        
    raise ValueError(f"Invalid IP address or range: {ip_range}")


def count_ips_in_range_static(ip_range: str) -> int:
    """
    Calculate number of IPs in a range without expanding it

    Supports: CIDR, hyphenated ranges (full and suffix), and single IPs
    """
    if not ip_range.strip():
        return 0

    # Try CIDR notation first (both IPv4 and IPv6)
    try:
        network = IPv4Network(ip_range, strict=False)
        return network.num_addresses
    except ValueError:
        pass

    try:
        network = IPv6Network(ip_range, strict=False)
        return network.num_addresses
    except ValueError:
        pass

    # Try IPv4 range notation like "192.168.1.1-10"
    if '-' in ip_range:
        parts = ip_range.split('-')
        if len(parts) != 2:
            return 0
        start_ip_str, end_part = parts[0].strip(), parts[1].strip()

        try:
            start_ip = IPv4Address(start_ip_str)
        except AddressValueError:
            return 0

        if '.' in end_part:
            try:
                end_ip = IPv4Address(end_part)
            except AddressValueError:
                return 0
            start_int = int(start_ip)
            end_int = int(end_ip)
            if start_int > end_int:
                return 0
            return end_int - start_int + 1
        else:
            try:
                end_suffix = int(end_part)
            except ValueError:
                return 0
            base_parts = start_ip_str.split('.')
            start_num = int(base_parts[-1])
            if end_suffix < start_num:
                return 0
            # Suffix range is limited to single subnet by original logic
            return max(0, min(end_suffix, 255) - start_num + 1)

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
        # True line-by-line streaming to prevent OOM on large target files
        with open(input_source, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        count = 0
                        for ip in validate_ip_range_static(line):
                            yield ip
                            count += 1
                        logger.debug(f"Line {line_num}: '{line}' -> {count} IPs")
                    except ValueError as e:
                        logger.warning(f"Skipping invalid line {line_num} ('{line}'): {e}")
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
        # FIX 5: Explicitly initialize all stat keys for deterministic reporting
        self.stats: Dict[str, int] = defaultdict(int)
        self._init_stats()
        
    def _init_stats(self):
        """Initialize all stat keys for deterministic reporting"""
        for key in ['successful_queries', 'timeout', 'connection_error', 'scan_errors', 'undetected', 
                    'process_status_success', 'model_info_success', 'port_closed']:
            self.stats[key] = 0
        for srv in ServerType:
            if srv != ServerType.UNKNOWN:
                self.stats[f"{srv.value}_count"] = 0

    async def check_port(self, ip: str, port: int) -> Tuple[bool, ScanStatus]:
        """
        Check if a specific port is open on an IP address
        
        Uses asyncio.wait_for with configurable timeout
        Restoration Note: OS-level TCP checks are significantly faster than aiohttp
        for filtering closed ports, preventing event-loop starvation during scans.
        """
        try:
            # asyncio.open_connection() uses the system TCP stack which handles RST
            # packets instantly, making it ideal for scanning closed ports.
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
            # Instant OS-level refusal for closed ports
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

    async def _single_probe_retry(self, session, url, parser, timeout_val, headers, ssl_setting):
        """Helper for endpoint probing with retry logic to reduce code duplication"""
        for attempt in range(self.retry_attempts):
            try:
                async with self.semaphore:
                    async with session.get(
                        url,
                        headers=headers,
                        ssl=ssl_setting,
                        timeout=timeout_val
                    ) as response:
                        if response.status == 200:
                            try:
                                data = await response.json()
                                return parser(data)
                            except aiohttp.ContentTypeError:
                                pass
                        return None
            except asyncio.TimeoutError:
                if attempt == self.retry_attempts - 1:
                    self.stats["timeout"] += 1
                    return None
                await asyncio.sleep(self.retry_delay * (2 ** attempt))
            except aiohttp.ClientConnectorError:
                self.stats["connection_error"] += 1
                return None
            except Exception:
                if attempt == self.retry_attempts - 1:
                    self.stats["connection_error"] += 1
                    return None
                await asyncio.sleep(self.retry_delay * (2 ** attempt))
        return None
            
    async def detect_server_type(
        self,
        ip: str,
        port: int,
        session: aiohttp.ClientSession
    ) -> Tuple[ServerType, List[str], ScanStatus]:
        """
        Detect which type of LLM server is running at the target
        
        Supports:
        - Ollama (/api/tags)
        - LM Studio (/v1/models)
        - TextGen WebUI (/api/info)
        """
        headers = {'User-Agent': 'LLMScanner/4.2'}
        ssl_setting = not self.disable_ssl_verify
        # Faster connect timeout since port is already verified open by check_port
        timeout_val = aiohttp.ClientTimeout(total=self.timeout, connect=1.5) 
        
        # Try Ollama first
        url_tags = f"http://{ip}:{port}/api/tags"
        ollama_models = await self._single_probe_retry(
            session, url_tags, 
            lambda d: [m.get('name', 'unknown') for m in d.get('models', [])],
            timeout_val, headers, ssl_setting
        )
        if ollama_models is not None:
            self.stats["successful_queries"] += 1
            self.stats[ServerType.OLLAMA.value + "_count"] += 1
            return (ServerType.OLLAMA, ollama_models, ScanStatus.SUCCESS)
            
        # Try LM Studio
        url_models = f"http://{ip}:{port}/v1/models"
        lm_models = await self._single_probe_retry(
            session, url_models,
            lambda d: [m.get('id', m.get('name', 'unknown')) for m in d.get('data', [])],
            timeout_val, headers, ssl_setting
        )
        if lm_models is not None:
            self.stats["successful_queries"] += 1
            self.stats[ServerType.LM_STUDIO.value + "_count"] += 1
            return (ServerType.LM_STUDIO, lm_models, ScanStatus.SUCCESS)
            
        # Try TextGen WebUI
        url_info = f"http://{ip}:{port}/api/info"
        tg_models = await self._single_probe_retry(
            session, url_info,
            lambda d: [d.get('loading_model', d.get('model_name', 'unknown'))],
            timeout_val, headers, ssl_setting
        )
        if tg_models is not None:
            self.stats["successful_queries"] += 1
            self.stats[ServerType.TEXTGEN_WEBUI.value + "_count"] += 1
            return (ServerType.TEXTGEN_WEBUI, tg_models, ScanStatus.SUCCESS)
            
        self.stats["undetected"] += 1
        return (ServerType.UNKNOWN, [], ScanStatus.UNDETECTED)
        
    async def get_process_status_ollama(
        self,
        ip: str,
        port: int,
        session: aiohttp.ClientSession
    ) -> Tuple[List[Dict], ScanStatus]:
        """Get currently loaded models from Ollama server (/api/ps) with retry logic"""
        url = f"http://{ip}:{port}/api/ps"
        headers = {'User-Agent': 'LLMScanner/4.2', 'Accept': 'application/json'}
        ssl_setting = not self.disable_ssl_verify
        timeout_val = aiohttp.ClientTimeout(total=self.timeout, connect=1.5)
        
        for attempt in range(self.retry_attempts):
            try:
                async with session.get(
                    url,
                    headers=headers,
                    ssl=ssl_setting,
                    timeout=timeout_val
                ) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            processes = data.get('models', [])
                            self.stats["process_status_success"] += 1
                            return (processes, ScanStatus.SUCCESS)
                        except aiohttp.ContentTypeError:
                            return ([], ScanStatus.INVALID_RESPONSE)
                    elif response.status == 404:
                        return ([], ScanStatus.SUCCESS)
                    else:
                        return ([], ScanStatus.INVALID_RESPONSE)
                        
            except asyncio.TimeoutError:
                if attempt < self.retry_attempts - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    await asyncio.sleep(wait_time)
                    continue
                self.stats["timeout"] += 1
                return ([], ScanStatus.TIMEOUT)
            except Exception as e:
                logger.debug(f"Error getting process status from {ip}:{port}: {e}")
                if attempt < self.retry_attempts - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    await asyncio.sleep(wait_time)
                    continue
                self.stats["connection_error"] += 1
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
        timeout_val = aiohttp.ClientTimeout(total=self.timeout, connect=1.5)
        
        for attempt in range(self.retry_attempts):
            try:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    ssl=ssl_setting,
                    timeout=timeout_val
                ) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            config = {
                                "system_prompt": data.get("system", ""),
                                "parameters": data.get("parameters", ""),
                                "template": data.get("template", "")
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
                self.stats["timeout"] += 1
                return (None, ScanStatus.TIMEOUT)
            except Exception as e:
                logger.debug(f"Error getting model info for {model_name} from {ip}:{port}: {e}")
                if attempt < self.retry_attempts - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    await asyncio.sleep(wait_time)
                    continue
                self.stats["connection_error"] += 1
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
            
            if server_type == ServerType.UNKNOWN:
                return None
                
            is_accessible = True
            
            process_list = []
            model_configs = []
            
            if deep_scan and models and server_type == ServerType.OLLAMA:
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
                is_accessible=is_accessible,
                status=model_status
            )
            
        except asyncio.TimeoutError:
            self.stats["timeout"] += 1
            return None
        except Exception as e:
            logger.debug(f"Unexpected error scanning {ip}:{port}: {e}")
            self.stats["scan_errors"] += 1
            return None
            
    async def _batch_iterator(
        self,
        ip_iterator: Iterator[Tuple[str, str]],
        batch_size: int = 1000
    ) -> AsyncIterator[List[Tuple[str, str]]]:
        """
        Yield batches of IPs from the iterator
        """
        batch: List[Tuple[str, str]] = []
        for ip_item in ip_iterator:
            batch.append(ip_item)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch
            
    def _count_ips_without_exhausting(self, input_source: str, is_file: bool = False) -> int:
        """
        Count total IPs without consuming the iterator
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
        batch_size: int = 500  # Reduced to 500 to prevent memory spikes and freezing
    ) -> List[ScanResult]:
        """
        Main scanning coroutine with improved resource management
        """
        total_ips = self._count_ips_without_exhausting(input_source, is_file)
        
        print(f"🔍 Scanning {total_ips} IPs for port {port}..." + (" [DEEP SCAN]" if deep_scan else ""))
        print("-" * 70, file=sys.stderr)
        
        if total_ips > 10000:
            confirm = input(f"\n⚠️  Warning: Scanning {total_ips} IPs may take significant time.\nContinue? (y/N): ").lower()
            if confirm != 'y':
                print("❌ Scan cancelled by user.", file=sys.stderr)
                return []
                
        results: List[ScanResult] = []
        results_lock = asyncio.Lock()
        start_time = time.time()
        completed = 0
        successes = 0
        
        # FIX 1: Connector limits tuned to match concurrency, preventing pool exhaustion
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent + 50,
            limit_per_host=20,
            ttl_dns_cache=300 if self.enable_dns_cache else None
        )
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout / 2)
        
        progress_bar = None
        if HAS_TQDM and show_progress:
            # FIX TQDM: disable auto-refresh during heavy I/O to prevent event-loop blocking
            progress_bar = tqdm.tqdm(total=total_ips, desc="Scanning", unit="IP", file=sys.stdout, mininterval=0.5)
            
        async with aiohttp.ClientSession(
            timeout=timeout_obj,
            connector=connector,
            headers={'Accept': 'application/json'}
        ) as session:
            ip_iterator = parse_ip_from_input(input_source, is_file=is_file)
            
            async for batch in self._batch_iterator(ip_iterator, batch_size=batch_size):
                tasks = [
                    asyncio.create_task(self.scan_single_ip(ip, version, port, session, deep_scan))
                    for ip, version in batch
                ]
                
                # FIX STABILITY: Use as_completed but handle exceptions safely
                for coro in asyncio.as_completed(tasks):
                    try:
                        result = await coro
                        completed += 1
                        
                        if result:
                            successes += 1
                            if result.is_accessible and result.models:
                                async with results_lock:
                                    results.append(result)
                                
                                # FIX TQDM: Use tqdm.tqdm.write() safely
                                if HAS_TQDM and show_progress:
                                    tqdm.tqdm.write(f"\n✅ {result.server_type.value.upper()} Server: {result.url}")
                                    tqdm.tqdm.write(f"   Models ({len(result.models)}): {', '.join(result.models[:5])}{'...' if len(result.models) > 5 else ''}")
                                    
                                    if deep_scan and result.process_list:
                                        tqdm.tqdm.write(f"   🔄 Loaded: {len(result.process_list)} model(s) in RAM/VRAM")
                                else:
                                    print(f"\n✅ {result.server_type.value.upper()} Server: {result.url}", flush=True)
                                    print(f"   Models ({len(result.models)}): {', '.join(result.models[:5])}{'...' if len(result.models) > 5 else ''}", flush=True)
                                        
                                    if deep_scan and result.process_list:
                                        print(f"   🔄 Loaded: {len(result.process_list)} model(s) in RAM/VRAM", flush=True)
                                    
                            elif result.is_accessible:
                                async with results_lock:
                                    results.append(result)
                                if HAS_TQDM and show_progress:
                                    tqdm.tqdm.write(f"✓ Open port at {result.url} - No models returned")
                                else:
                                    print(f"✓ Open port at {result.url} - No models returned", flush=True)
                            else:
                                if HAS_TQDM and show_progress:
                                    tqdm.tqdm.write(f"❌ Invalid server at {result.url}")
                                else:
                                    print(f"❌ Invalid server at {result.url}", flush=True)
                        
                        if progress_bar:
                            progress_bar.update(1)
                        elif show_progress and (completed % 50 == 0 or completed == total_ips):
                            elapsed = time.time() - start_time
                            rate = completed / elapsed if elapsed > 0 else 0
                            percent = (completed / total_ips) * 100 if total_ips > 0 else 0
                            print(f"\r📈 Progress: {completed}/{total_ips} ({percent:.1f}%) | Rate: {rate:.1f} IPs/sec | Successes: {successes}", 
                                  end='', flush=True, file=sys.stderr)
                                  
                    except asyncio.CancelledError:
                        # Cancel remaining tasks on interruption
                        for t in tasks:
                            t.cancel()
                        raise
                    
                    except Exception as e:
                        logger.error(f"Error processing task in batch: {e}")
                        continue
                
                # FIX FREEZING: Yield control to event loop between batches to prevent starvation
                await asyncio.sleep(0)
        
        if progress_bar:
            progress_bar.close()
        
        duration = time.time() - start_time
        print(f"\n\n🏁 Scan completed in {duration:.2f} seconds", file=sys.stderr)
        
        print("\n📊 Scan Statistics:", file=sys.stderr)
        print(f"  • Total IPs scanned:     {total_ips}", file=sys.stderr)
        print(f"  • Successful queries:    {self.stats.get('successful_queries', 0)}", file=sys.stderr)
        print(f"  • Timeouts:              {self.stats.get('timeout', 0)}", file=sys.stderr)
        print(f"  • Connection errors:     {self.stats.get('connection_error', 0)}", file=sys.stderr)
        print(f"  • Undetected/Filtered:   {self.stats.get('undetected', 0)}", file=sys.stderr)
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
    parser.add_argument("--batch-size", type=int, default=500, help="Batch size for memory optimization (default: 500)")
    
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
    except asyncio.CancelledError:
        print("\n\n⚠️  Scan cancelled by user (AsyncEvent)", file=sys.stderr)
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