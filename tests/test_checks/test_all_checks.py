"""Tests for security check modules.

This module imports and runs all individual check tests.
For new tests, add them to the specific test_*.py files in this directory.
"""

# Import all check tests to ensure they are registered with pytest
# Each module contains tests for a specific security check

# These imports ensure tests are discovered by pytest
from tests.test_checks.test_system import TestSystemChecks
from tests.test_checks.test_updates import TestUpdatesChecks
from tests.test_checks.test_firewall import TestFirewallChecks
from tests.test_checks.test_autorun import TestAutorunChecks
from tests.test_checks.test_users import TestUsersChecks
from tests.test_checks.test_services import TestServicesChecks
from tests.test_checks.test_registry import TestRegistryChecks
from tests.test_checks.test_network import TestNetworkChecks
from tests.test_checks.test_security_sw import TestSecuritySoftwareChecks
from tests.test_checks.test_events import TestEventsChecks

# Re-export all test classes for pytest discovery
__all__ = [
    'TestSystemChecks',
    'TestUpdatesChecks',
    'TestFirewallChecks',
    'TestAutorunChecks',
    'TestUsersChecks',
    'TestServicesChecks',
    'TestRegistryChecks',
    'TestNetworkChecks',
    'TestSecuritySoftwareChecks',
    'TestEventsChecks',
]
