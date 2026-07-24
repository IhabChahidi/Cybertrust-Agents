"""LLM role adapters: Generator (Copilot Studio), Verifier, Validator.

Each role is defined by an abstract interface in base.py. mock_*.py implements
deterministic stand-ins used while there is no Copilot Studio / external LLM
access. real_stub.py is the placeholder to fill in once access is granted —
the orchestrator only depends on the abstract interfaces, so swapping mock for
real requires no change outside this package and config.py.
"""
