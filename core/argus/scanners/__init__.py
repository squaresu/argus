"""Every module in this folder that defines SCANNER is a scanner Argus can use: add a file to add a tool."""

import importlib
import pkgutil

from .base import Scanner

_cache = None


def all_scanners() -> list[Scanner]:
    global _cache
    if _cache is None:
        found = []
        for mod in pkgutil.iter_modules(__path__):
            if mod.name == 'base':
                continue
            scanner = getattr(importlib.import_module(f'{__name__}.{mod.name}'), 'SCANNER', None)
            if isinstance(scanner, Scanner):
                found.append(scanner)
        _cache = sorted(found, key=lambda s: (s.order, s.id))
    return _cache


def get(scanner_id):
    return next((s for s in all_scanners() if s.id == scanner_id), None)
