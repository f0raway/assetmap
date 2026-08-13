"""External data-provider adapters used by acquisition services.

Collectors contain only provider-specific request, parsing and checkpoint
logic.  Pipeline policy belongs to ``services.acquisition``; CLI and stages
must not call collectors directly.
"""
