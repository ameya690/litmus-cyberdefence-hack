"""Litmus file-read oracle.

The trust anchor of the whole system. It:

  1. plants a cryptographically-random flag that the attacker is NEVER told, and
  2. verifies a proof by checking whether the *target's own response bytes*
     contain that exact flag.

Because the flag is random (unguessable) and never disclosed to the attacker,
the only way for it to appear in the target's response is for the attacker to
have actually read the challenge file through the vulnerability. The oracle
checks code, not an LLM's claim -- hallucinations and echoes cannot pass.
"""
import os
import secrets

FLAG_PREFIX = "FLAG-"


class FileReadOracle:
    def __init__(self, secret_path):
        self.secret_path = secret_path
        self._flag = None  # held private; never handed to the attacker

    def plant(self):
        """Generate a fresh random flag and write it to the challenge location.

        Returns the flag for the OPERATOR's live-demo display only (BUILD_PLAN
        demo spine: "plant the secret live, on screen"). It is never passed to
        the attacker agent or the exploit.
        """
        self._flag = FLAG_PREFIX + secrets.token_hex(16)
        os.makedirs(os.path.dirname(self.secret_path), exist_ok=True)
        with open(self.secret_path, "w") as f:
            f.write(self._flag)
        return self._flag

    @property
    def flag(self):
        return self._flag

    def verify(self, response):
        """Accept iff the planted flag appears in the bytes the target returned."""
        if self._flag is None:
            raise RuntimeError("verify() called before plant()")
        data = response if isinstance(response, (bytes, bytearray)) else str(response).encode()
        return self._flag.encode() in data
