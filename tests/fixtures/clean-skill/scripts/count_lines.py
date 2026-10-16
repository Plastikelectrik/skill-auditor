#!/usr/bin/env python3
"""Cuenta las líneas añadidas y eliminadas de un archivo de diff."""
import sys


def main(path: str) -> None:
    added = removed = 0
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("+") and not line.startswith("+++"):
                added += 1
            elif line.startswith("-") and not line.startswith("---"):
                removed += 1
    print(f"añadidas: {added}, eliminadas: {removed}")


if __name__ == "__main__":
    main(sys.argv[1])
