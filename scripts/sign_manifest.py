#!/usr/bin/env python3
"""Sign a plugin manifest with Ed25519.

Usage:
    python scripts/sign_manifest.py <plugin_dir> [--generate-key] [--key KEY_HEX]

This adds "signature" and "public_key" fields to the plugin.json manifest,
enabling Ed25519 signature verification when loading plugins.

Examples:
    # Generate a new keypair and sign
    python scripts/sign_manifest.py plugins/test_plugin --generate-key

    # Sign with an existing private key
    python scripts/sign_manifest.py plugins/test_plugin --key <hex_private_key>

    # Verify an existing signature
    python scripts/sign_manifest.py plugins/test_plugin --verify-only
"""
import argparse
import hashlib
import json
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False


def compute_module_checksum(plugin_dir: str, entry_point: str) -> str:
    """Compute SHA-256 checksum of the entry module."""
    module_path = os.path.join(plugin_dir, f"{entry_point}.py")
    if not os.path.exists(module_path):
        print(f"Error: entry module not found at {module_path}")
        sys.exit(1)
    with open(module_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def compute_signature_content(meta: dict, module_checksum: str) -> str:
    """Compute the canonical content to sign (same as plugin_manager.py)."""
    hooks = meta.get("hooks", [])
    return json.dumps({
        "name": meta.get("name", ""),
        "version": meta.get("version", ""),
        "entry_point": meta.get("entry_point", ""),
        "hooks": sorted(hooks) if isinstance(hooks, list) else [],
        "module_sha256": module_checksum,
    }, sort_keys=True, separators=(",", ":"))


def sign_manifest(plugin_dir: str, private_key_hex: str | None = None, generate_key: bool = False) -> None:
    """Sign a plugin.json manifest with Ed25519."""
    if not HAS_NACL:
        print("Error: pynacl is required for manifest signing. Install with: pip install pynacl")
        sys.exit(1)

    manifest_path = os.path.join(plugin_dir, "plugin.json")
    if not os.path.exists(manifest_path):
        print(f"Error: {manifest_path} not found")
        sys.exit(1)

    with open(manifest_path) as f:
        meta = json.load(f)

    entry_point = meta.get("entry_point")
    if not entry_point:
        print("Error: manifest missing 'entry_point' field")
        sys.exit(1)

    module_checksum = compute_module_checksum(plugin_dir, entry_point)
    message = compute_signature_content(meta, module_checksum)

    # Generate or use provided key
    if generate_key:
        signing_key = SigningKey.generate()
        private_key_hex = signing_key.encode().hex()
        public_key_hex = signing_key.verify_key.encode().hex()
        print("Generated Ed25519 keypair:")
        print(f"  Private key: {private_key_hex}")
        print(f"  Public key:  {public_key_hex}")
        print("\n⚠️  Save the private key securely. It is NOT stored by this tool.")
    elif private_key_hex:
        signing_key = SigningKey(bytes.fromhex(private_key_hex))
        public_key_hex = signing_key.verify_key.encode().hex()
    else:
        print("Error: specify --generate-key or --key <hex_private_key>")
        sys.exit(1)

    # Sign
    signed = signing_key.sign(message.encode())
    signature_hex = signed.signature.hex()

    # Verify our own signature
    verify_key = VerifyKey(bytes.fromhex(public_key_hex))
    try:
        verify_key.verify(message.encode(), bytes.fromhex(signature_hex))
    except BadSignatureError:
        print("Error: signature verification failed immediately after signing!")
        sys.exit(1)

    # Update manifest
    meta["public_key"] = public_key_hex
    meta["signature"] = signature_hex

    with open(manifest_path, "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")

    print(f"\nManifest signed: {manifest_path}")
    print(f"  Public key: {public_key_hex[:16]}...")
    print(f"  Signature:  {signature_hex[:16]}...")


def verify_manifest(plugin_dir: str) -> None:
    """Verify a signed plugin.json manifest."""
    if not HAS_NACL:
        print("Error: pynacl is required for verification. Install with: pip install pynacl")
        sys.exit(1)

    manifest_path = os.path.join(plugin_dir, "plugin.json")
    if not os.path.exists(manifest_path):
        print(f"Error: {manifest_path} not found")
        sys.exit(1)

    with open(manifest_path) as f:
        meta = json.load(f)

    entry_point = meta.get("entry_point")
    pub_key_hex = meta.get("public_key")
    sig_hex = meta.get("signature")

    if not all([entry_point, pub_key_hex, sig_hex]):
        print("Error: manifest missing required signature fields (public_key, signature)")
        sys.exit(1)

    module_checksum = compute_module_checksum(plugin_dir, entry_point)
    message = compute_signature_content(meta, module_checksum)

    verify_key = VerifyKey(bytes.fromhex(pub_key_hex))
    try:
        verify_key.verify(message.encode(), bytes.fromhex(sig_hex))
        print(f"✓ Manifest signature VALID: {manifest_path}")
        print(f"  Public key: {pub_key_hex[:16]}...")
        print(f"  Signature:  {sig_hex[:16]}...")
    except BadSignatureError:
        print(f"✗ Manifest signature INVALID: {manifest_path}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Sign or verify plugin manifests with Ed25519")
    parser.add_argument("plugin_dir", help="Path to plugin directory containing plugin.json")
    parser.add_argument("--generate-key", action="store_true", help="Generate a new Ed25519 keypair and sign")
    parser.add_argument("--key", help="Hex-encoded Ed25519 private key for signing")
    parser.add_argument("--verify-only", action="store_true", help="Only verify an existing signature")
    args = parser.parse_args()

    if args.verify_only:
        verify_manifest(args.plugin_dir)
    else:
        sign_manifest(args.plugin_dir, private_key_hex=args.key, generate_key=args.generate_key)


if __name__ == "__main__":
    main()
