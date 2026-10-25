from .atomic_rotation import AtomicRotationStrategy
from .base import RefreshResult, RefreshStrategy
from .grace_rotation import GraceWindowStrategy
from .naive_rotation import NaiveRotationStrategy
from .static import StaticStrategy

STRATEGIES: dict[str, type[RefreshStrategy]] = {
    StaticStrategy.name: StaticStrategy,
    NaiveRotationStrategy.name: NaiveRotationStrategy,
    AtomicRotationStrategy.name: AtomicRotationStrategy,
    GraceWindowStrategy.name: GraceWindowStrategy,
}

__all__ = [
    "AtomicRotationStrategy",
    "GraceWindowStrategy",
    "NaiveRotationStrategy",
    "RefreshResult",
    "RefreshStrategy",
    "StaticStrategy",
    "STRATEGIES",
]
