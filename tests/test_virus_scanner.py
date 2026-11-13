"""Tests for VirusScanner service."""

from unittest.mock import MagicMock, patch

from services.virus_scanner import ScanResult, VirusScanner, get_virus_scanner


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_clean_result(self):
        r = ScanResult(is_infected=False, virus_name=None, scan_time_ms=1.0, file_size=100)
        assert r.is_clean is True
        assert r.is_infected is False
        assert r.virus_name is None

    def test_infected_result(self):
        r = ScanResult(is_infected=True, virus_name="Eicar-Test", scan_time_ms=5.0, file_size=100)
        assert r.is_clean is False
        assert r.is_infected is True
        assert r.virus_name == "Eicar-Test"

    def test_error_result(self):
        r = ScanResult(
            is_infected=False,
            virus_name=None,
            scan_time_ms=0.0,
            file_size=50,
            error="Scanner not available",
        )
        assert r.is_clean is False  # error present means not clean
        assert r.is_infected is False


class TestScanResultCompleted:
    """``completed`` is the only field that separates scanned from not-scanned.

    Every failure path returns ``is_infected=False`` because a scanner that
    never ran cannot report an infection, so a caller gating on ``is_infected``
    alone stores unscanned files and reports them as scanned.
    """

    def test_a_verdict_is_completed(self):
        r = ScanResult(is_infected=False, virus_name=None, scan_time_ms=1.0, file_size=1)
        assert r.completed is True

    def test_an_infection_is_completed(self):
        r = ScanResult(is_infected=True, virus_name="Eicar", scan_time_ms=1.0, file_size=1)
        assert r.completed is True

    def test_an_error_is_not_completed(self):
        r = ScanResult(
            is_infected=False,
            virus_name=None,
            scan_time_ms=0.0,
            file_size=1,
            error="Error 61 connecting to clamav:3310. Connection refused.",
        )
        assert r.completed is False
        # The trap: this reads exactly like a clean file.
        assert r.is_infected is False


class TestVirusScannerInit:
    """Test VirusScanner initialization."""

    def test_init_without_clamd(self):
        with patch("services.virus_scanner.CLAMD_AVAILABLE", False):
            scanner = VirusScanner()
            assert scanner.scanner is None

    def test_init_with_clamd_success(self):
        mock_scanner = MagicMock()
        with (
            patch("services.virus_scanner.CLAMD_AVAILABLE", True),
            patch("services.virus_scanner.clamd") as mock_clamd,
        ):
            mock_clamd.ClamdNetworkSocket.return_value = mock_scanner
            scanner = VirusScanner(host="localhost", port=3310)
            assert scanner.scanner is mock_scanner

    def test_init_with_clamd_connection_error(self):
        with (
            patch("services.virus_scanner.CLAMD_AVAILABLE", True),
            patch("services.virus_scanner.clamd") as mock_clamd,
        ):
            mock_clamd.ClamdNetworkSocket.side_effect = Exception("Connection refused")
            scanner = VirusScanner()
            assert scanner.scanner is None


class TestScanBytes:
    """Test byte stream scanning."""

    def test_scan_no_scanner(self):
        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = None
        scanner.host = "localhost"
        scanner.port = 3310
        scanner.timeout = 5.0
        scanner.max_retries = 3

        result = scanner.scan_bytes(b"test data")
        assert result.is_infected is False
        assert result.error == "Scanner not available"
        assert result.completed is False

    def test_scan_clean(self):
        mock_clamd = MagicMock()
        mock_clamd.instream.return_value = {"stream": ("OK", None)}

        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = mock_clamd
        scanner.max_retries = 3
        scanner.host = "localhost"
        scanner.port = 3310
        scanner.timeout = 5.0

        result = scanner.scan_bytes(b"clean data", filename="test.txt")
        assert result.is_infected is False
        assert result.virus_name is None
        assert result.completed is True  # control: a real verdict IS completed

    def test_scan_infected(self):
        mock_clamd = MagicMock()
        mock_clamd.instream.return_value = {"stream": ("FOUND", "Eicar-Test-Signature")}

        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = mock_clamd
        scanner.max_retries = 3
        scanner.host = "localhost"
        scanner.port = 3310
        scanner.timeout = 5.0

        result = scanner.scan_bytes(b"virus data", filename="evil.exe")
        assert result.is_infected is True
        assert result.virus_name == "Eicar-Test-Signature"

    def test_scan_no_stream_in_result(self):
        """A reply with no ``stream`` key carries no verdict -> not completed."""
        mock_clamd = MagicMock()
        mock_clamd.instream.return_value = {}

        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = mock_clamd
        scanner.max_retries = 3
        scanner.host = "localhost"
        scanner.port = 3310
        scanner.timeout = 5.0

        result = scanner.scan_bytes(b"data")
        assert result.is_infected is False
        assert result.virus_name is None
        assert result.completed is False
        assert result.error is not None

    def test_scan_with_retry_on_connection_error(self):
        mock_clamd = MagicMock()
        mock_clamd.instream.side_effect = [
            ConnectionError("Connection lost"),
            {"stream": ("OK", None)},
        ]

        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = mock_clamd
        scanner.max_retries = 3
        scanner.host = "localhost"
        scanner.port = 3310
        scanner.timeout = 5.0

        with patch("services.virus_scanner.time.sleep"):
            with patch.object(scanner, "_initialize_scanner"):
                result = scanner.scan_bytes(b"data")
                assert result.is_infected is False

    def test_scan_all_retries_fail(self):
        mock_clamd = MagicMock()
        mock_clamd.instream.side_effect = ConnectionError("Connection lost")

        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = mock_clamd
        scanner.max_retries = 2
        scanner.host = "localhost"
        scanner.port = 3310
        scanner.timeout = 5.0

        with patch("services.virus_scanner.time.sleep"):
            with patch.object(scanner, "_initialize_scanner"):
                result = scanner.scan_bytes(b"data")
                assert result.error is not None
                assert result.completed is False

    def test_scan_unexpected_exception(self):
        mock_clamd = MagicMock()
        mock_clamd.instream.side_effect = RuntimeError("Unexpected")

        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = mock_clamd
        scanner.max_retries = 1
        scanner.host = "localhost"
        scanner.port = 3310
        scanner.timeout = 5.0

        result = scanner.scan_bytes(b"data")
        assert result.error is not None
        assert result.completed is False


class TestPing:
    """Test ClamAV ping."""

    def test_ping_success(self):
        mock_clamd = MagicMock()
        mock_clamd.ping.return_value = "PONG"

        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = mock_clamd

        assert scanner.ping() is True

    def test_ping_wrong_response(self):
        mock_clamd = MagicMock()
        mock_clamd.ping.return_value = "ERROR"

        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = mock_clamd

        assert scanner.ping() is False

    def test_ping_no_scanner(self):
        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = None
        assert scanner.ping() is False

    def test_ping_exception(self):
        mock_clamd = MagicMock()
        mock_clamd.ping.side_effect = Exception("Connection refused")

        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = mock_clamd

        assert scanner.ping() is False


class TestHealthCheck:
    """Test ClamAV health check."""

    def test_healthy(self):
        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = MagicMock()
        scanner.scanner.ping.return_value = "PONG"

        healthy, message, latency = scanner.health_check()
        assert healthy is True
        assert "healthy" in message.lower()

    def test_unhealthy(self):
        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = MagicMock()
        scanner.scanner.ping.return_value = "ERROR"

        healthy, message, latency = scanner.health_check()
        assert healthy is False

    def test_health_exception(self):
        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = None

        healthy, message, latency = scanner.health_check()
        assert healthy is False


class TestInitializeScannerClamdUnavailable:
    """Test _initialize_scanner when clamd is not available."""

    def test_initialize_scanner_noop_without_clamd(self):
        """_initialize_scanner should be a no-op when CLAMD_AVAILABLE is False."""
        with (
            patch("services.virus_scanner.CLAMD_AVAILABLE", True),
            patch("services.virus_scanner.clamd") as mock_clamd,
        ):
            mock_clamd.ClamdNetworkSocket.return_value = MagicMock()
            scanner = VirusScanner(host="localhost", port=3310)
            # Now simulate clamd becoming unavailable
            with patch("services.virus_scanner.CLAMD_AVAILABLE", False):
                scanner._initialize_scanner()
                # scanner.scanner should remain unchanged -- _initialize_scanner
                # returns early


class TestHealthCheckException:
    """Test health_check exception branch in VirusScanner."""

    def test_health_check_ping_raises(self):
        """health_check should handle exceptions from ping()."""
        scanner = VirusScanner.__new__(VirusScanner)
        scanner.scanner = MagicMock()
        scanner.scanner.ping.side_effect = Exception("Socket closed")

        healthy, message, latency = scanner.health_check()
        assert healthy is False
        assert "failed" in message.lower()
        assert latency >= 0


class TestGetVirusScanner:
    """Test singleton getter."""

    def test_returns_scanner(self):
        with patch("services.virus_scanner._virus_scanner", None):
            with patch("services.virus_scanner.VirusScanner") as mock_cls:
                mock_instance = MagicMock()
                mock_cls.return_value = mock_instance
                result = get_virus_scanner()
                assert result is mock_instance
