"""Allow ``python -m why`` as an alias for the ``why`` console script."""

from why.cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
