# Re-export of the psptool-rs native implementation at the upstream PSPTool
# module path (see crates/psptool-py/DEVIATIONS.md). No logic lives here.

from ._native import (
    KeyId,
    KeyType,
    PrivateKeyDict,
    ReversedSignature,
    Rsa2048PrivateKey,
    Rsa2048PublicKey,
    Rsa4096PrivateKey,
    Rsa4096PublicKey,
    RsaPrivateKey,
    RsaPublicKey,
    Signature,
)

# Upstream's abstract bases; the RSA classes are the only implementations.
PublicKey = RsaPublicKey
PrivateKey = RsaPrivateKey

__all__ = [
    "KeyType",
    "PublicKey",
    "PrivateKey",
    "RsaPublicKey",
    "RsaPrivateKey",
    "Rsa2048PublicKey",
    "Rsa2048PrivateKey",
    "Rsa4096PublicKey",
    "Rsa4096PrivateKey",
    "PrivateKeyDict",
    "KeyId",
    "Signature",
    "ReversedSignature",
]
