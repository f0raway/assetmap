"""Independently runnable business stages used by the assetmap pipeline.

Each module in this package owns a single business stage and exposes both a
``run`` function for the pipeline and a ``python -m`` entry point for focused
debugging.  The entry points deliberately reuse the production stage service.
"""
