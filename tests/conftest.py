import pytest

from vouch.clock import ManualClock
from vouch.harness import Harness
from vouch.identity import generate_private_key
from vouch.lease import LeaseManager
from vouch.ledger import Ledger
from vouch.schema import TaskSpec


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
