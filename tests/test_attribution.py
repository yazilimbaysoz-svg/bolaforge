"""Attribution and public metadata tests.

Baysöz Labs <baysozlabs@proton.me>
"""

from bolaforge import ATTRIBUTION, EMAIL, LAB, __version__
from bolaforge.attribution import REPOSITORY


def test_attribution_is_explicit() -> None:
    assert LAB == "Baysöz Labs"
    assert EMAIL == "baysozlabs@proton.me"
    assert ATTRIBUTION == "Baysöz Labs <baysozlabs@proton.me>"
    assert "baysozlabs@proton.me" in REPOSITORY or REPOSITORY.startswith("https://github.com/")


def test_semantic_version() -> None:
    assert __version__.count(".") == 2
