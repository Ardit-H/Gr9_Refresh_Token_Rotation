from .atomic_rotation import AtomicRotationStrategy
from .base import RefreshResult, RefreshStrategy
from .naive_rotation import NaiveRotationStrategy
from .static import StaticStrategy

STRATEGIES: dict[str, type[RefreshStrategy]] = {
    StaticStrategy.name: StaticStrategy,
    NaiveRotationStrategy.name: NaiveRotationStrategy,
    AtomicRotationStrategy.name: AtomicRotationStrategy,
}

__all__ = [
    "AtomicRotationStrategy",
    "NaiveRotationStrategy",
    "RefreshResult",
    "RefreshStrategy",
    "StaticStrategy",
    "STRATEGIES",
]
