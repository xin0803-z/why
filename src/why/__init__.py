"""why — explain Linux access denials layer by layer.

The whole point of this package is to answer one question well:

    "Permission denied — but which layer denied me, and how do I fix it?"

Layout
------
``why.parsers``   pure, dependency-free parsers (mountinfo, POSIX ACL xattr,
                  /proc/PID/status, capability masks, SELinux AVC records,
                  AppArmor denials, FS_IOC_GETFLAGS bit names, UNIX mode bits).
``why.collect``   the only module that touches the live system (Linux).
``why.checks``    one module per attribution layer; each returns a LayerResult.
``why.report``    rendering: human text and JSON.
``why.cli``       argument parsing and the exit-code contract.
"""

__version__ = "0.1.1"
__all__ = ["__version__"]
