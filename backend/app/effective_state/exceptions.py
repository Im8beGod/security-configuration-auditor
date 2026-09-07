class EffectiveStateError(Exception):
    """Base error for the persisted-fact effective-state boundary."""


class EffectiveStateValidationError(EffectiveStateError):
    pass


class EffectiveStateNotFoundError(EffectiveStateError):
    pass
