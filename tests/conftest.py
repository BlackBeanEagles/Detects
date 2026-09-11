import pytest

from detects.clock import ManualClock
from detects.harness import Harness
from detects.identity import generate_private_key
from detects.lease import LeaseManager
from detects.ledger import Ledger
from detects.schema import TaskSpec


@pytest.fixture
def clock():
    return ManualClock()


@pytest.fixture
def key():
    return generate_private_key()


@pytest.fixture
def ledger():
    return Ledger()


@pytest.fixture
def leases():
    return LeaseManager()


@pytest.fixture
def harness(key, ledger, leases, clock):
    return Harness(private_key=key, ledger=ledger, leases=leases, clock=clock)


@pytest.fixture
def sum_spec():
    return TaskSpec(
        name="sum_range",
        inputs={"n": 100},
        declared_postconditions=["output_equals_closed_form"],
    )
