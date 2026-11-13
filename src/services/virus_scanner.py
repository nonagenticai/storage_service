"""
Virus scanning service using ClamAV.
Scans uploaded files for malware before storage.
"""

import io
import logging
import time
import types as _types
from dataclasses import dataclass

try:
    import clamd

    CLAMD_AVAILABLE = True
except ImportError:
    CLAMD_AVAILABLE = False
    clamd: _types.ModuleType | None = None

from config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of a virus scan operation."""

    is_infected: bool
    virus_name: str | None
    scan_time_ms: float
    file_size: int
    error: str | None = None

    @property
    def is_clean(self) -> bool:
        """Returns True if file is clean (not infected and no errors)."""
        return not self.is_infected and self.error is None

    @property
    def completed(self) -> bool:
        """True only when the scanner actually returned a verdict.

        ``is_infected=False`` alone is NOT evidence of a clean file: every
        failure path in :meth:`VirusScanner.scan_bytes` (daemon unreachable,
        retries exhausted, malformed reply) also returns ``is_infected=False``
        because there is nothing else it *can* return. ``error`` is the only
        field that distinguishes "scanned and clean" from "never scanned", so
        callers must gate on this property before reporting a file as scanned.
        """
        return self.error is None


class VirusScanner:
    """
    ClamAV-based virus scanner for uploaded files.
    """

    def __init__(
        self,
        host: str = "clamav",
        port: int = 3310,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """Initialize virus scanner."""
        if not CLAMD_AVAILABLE:
            logger.warning("clamd library not available, virus scanning disabled")
            self.scanner = None
            return

        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self.scanner = None
        self._initialize_scanner()

    def _initialize_scanner(self) -> None:
        """Initialize ClamAV scanner connection."""
        if not CLAMD_AVAILABLE or clamd is None:
            return

        try:
            self.scanner = clamd.ClamdNetworkSocket(
                host=self.host,
                port=self.port,
                timeout=self.timeout,
            )
            logger.info(f"ClamAV scanner initialized at {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to initialize ClamAV scanner: {e}")
            self.scanner = None

    def scan_bytes(self, data: bytes, filename: str = "stream") -> ScanResult:
        """
        Scan byte stream for viruses.

        Args:
            data: Byte stream to scan
            filename: Optional filename for logging

        Returns:
            ScanResult with scan details
        """
        if not self.scanner:
            return ScanResult(
                is_infected=False,
                virus_name=None,
                scan_time_ms=0.0,
                file_size=len(data),
                error="Scanner not available",
            )

        file_size = len(data)
        start_time = time.time()

        try:
            # Scan with retries
            for attempt in range(self.max_retries):
                try:
                    result = self.scanner.instream(io.BytesIO(data))
                    break
                except (ConnectionError, OSError) as e:
                    if attempt < self.max_retries - 1:
                        logger.warning(f"Scan attempt {attempt + 1} failed, retrying: {e}")
                        time.sleep(1 * (attempt + 1))
                        self._initialize_scanner()
                    else:
                        raise

            scan_time_ms = (time.time() - start_time) * 1000

            # Parse result. A reply with no ``stream`` key carries no verdict —
            # report it as an error rather than as a clean scan, so the caller
            # fails closed instead of storing an unscanned file.
            status = result.get("stream")
            if not status:
                return ScanResult(
                    is_infected=False,
                    virus_name=None,
                    scan_time_ms=scan_time_ms,
                    file_size=file_size,
                    error="Scanner returned no verdict",
                )

            scan_status, virus_name = status

            if scan_status == "FOUND":
                logger.warning(f"Virus detected in {filename}: {virus_name}")
                return ScanResult(
                    is_infected=True,
                    virus_name=virus_name,
                    scan_time_ms=scan_time_ms,
                    file_size=file_size,
                )
            else:
                logger.debug(f"File {filename} is clean ({scan_time_ms:.2f}ms)")
                return ScanResult(
                    is_infected=False,
                    virus_name=None,
                    scan_time_ms=scan_time_ms,
                    file_size=file_size,
                )

        except Exception as e:
            scan_time_ms = (time.time() - start_time) * 1000
            logger.error(f"Virus scan failed for {filename}: {e}")
            return ScanResult(
                is_infected=False,
                virus_name=None,
                scan_time_ms=scan_time_ms,
                file_size=file_size,
                error=str(e),
            )

    def ping(self) -> bool:
        """Check if ClamAV daemon is available."""
        if not self.scanner:
            return False

        try:
            response = self.scanner.ping()
            return response == "PONG"
        except Exception as e:
            logger.debug(f"ClamAV ping failed: {e}")
            return False

    def health_check(self) -> tuple[bool, str, float]:
        """
        Check ClamAV health.

        Returns:
            Tuple of (is_healthy, message, latency_ms)
        """
        start = time.time()
        try:
            if self.ping():
                latency = (time.time() - start) * 1000
                return True, "ClamAV is healthy", latency
            else:
                latency = (time.time() - start) * 1000
                return False, "ClamAV ping failed", latency
        except Exception as e:
            latency = (time.time() - start) * 1000
            return False, f"ClamAV health check failed: {e}", latency


# Global scanner instance
_virus_scanner: VirusScanner | None = None


def get_virus_scanner() -> VirusScanner:
    """Get global virus scanner instance."""
    global _virus_scanner
    if _virus_scanner is None:
        settings = get_settings()
        _virus_scanner = VirusScanner(
            host=settings.clamav_host,
            port=settings.clamav_port,
            timeout=settings.clamav_timeout,
        )
    return _virus_scanner
