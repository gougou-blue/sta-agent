#!/usr/bin/env python3
"""
Setup Intel SHA384 SSL certificate bundle for GNAI API access.

Downloads the Intel SHA384 Trust Chain and combines it with system CA
certificates to create a bundle that works with GNAI's SSL.

Usage:
    python setup_certs.py

After running, add to your shell profile:
    csh:  setenv REQUESTS_CA_BUNDLE ~/intel-certs/intel-ca-bundle.crt
          setenv SSL_CERT_FILE ~/intel-certs/intel-ca-bundle.crt
    bash: export REQUESTS_CA_BUNDLE=~/intel-certs/intel-ca-bundle.crt
          export SSL_CERT_FILE=~/intel-certs/intel-ca-bundle.crt
"""

import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path


def main():
    cert_dir = Path.home() / "intel-certs"
    cert_dir.mkdir(exist_ok=True)
    bundle_path = cert_dir / "intel-ca-bundle.crt"

    if bundle_path.exists():
        print(f"Bundle already exists: {bundle_path}")
        resp = input("Recreate? [y/N] ").strip().lower()
        if resp != "y":
            print("Keeping existing bundle.")
            return

    # Download Intel SHA384 trust chain
    zip_url = "http://certificates.intel.com/repository/certificates/TrustBundles/IntelSHA384TrustChain-Base64.zip"
    zip_path = cert_dir / "certs.zip"

    print(f"Downloading Intel SHA384 Trust Chain...")
    # Check if zip was pre-downloaded (e.g. manually placed)
    pre_downloaded = cert_dir / "certs.zip"
    if pre_downloaded.exists() and pre_downloaded.stat().st_size > 1000:
        print(f"  Found pre-downloaded {pre_downloaded}, using it.")
        zip_path = pre_downloaded
    else:
        proxy = os.environ.get("http_proxy", os.environ.get("HTTP_PROXY", ""))
        curl_args = ["curl", "-L", "-f", "-o", str(zip_path)]
        if proxy:
            curl_args += ["-x", proxy]
        curl_args.append(zip_url)

        try:
            subprocess.run(curl_args, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Try with Intel proxy
            try:
                subprocess.run(
                    ["curl", "-L", "-f", "-x", "http://proxy-dmz.intel.com:912",
                     "-o", str(zip_path), zip_url],
                    check=True,
                )
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Try wget as fallback
                try:
                    subprocess.run(
                        ["wget", "-O", str(zip_path), zip_url],
                        check=True,
                    )
                except (subprocess.CalledProcessError, FileNotFoundError):
                    print("Error: Could not download certificates.")
                    print(f"  Download manually and place at: {cert_dir}/certs.zip")
                    print(f"  URL: {zip_url}")
                    sys.exit(1)

    if not zip_path.exists() or zip_path.stat().st_size == 0:
        print("Error: Download failed — empty or missing zip file.")
        sys.exit(1)

    # Extract
    print("Extracting certificates...")
    with zipfile.ZipFile(str(zip_path), "r") as zf:
        zf.extractall(str(cert_dir))

    # Get system CA bundle
    system_cas = ""
    try:
        import certifi
        ca_path = certifi.where()
        with open(ca_path, "r") as f:
            system_cas = f.read()
        print(f"Loaded system CAs from certifi: {ca_path}")
    except ImportError:
        # Try common system locations
        for sys_path in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem",
        ]:
            if os.path.isfile(sys_path):
                with open(sys_path, "r") as f:
                    system_cas = f.read()
                print(f"Loaded system CAs from: {sys_path}")
                break
        if not system_cas:
            print("Warning: No system CA bundle found. Bundle will only contain Intel certs.")

    # Combine
    combined = system_cas + "\n" if system_cas else ""
    intel_count = 0

    for cert_file in cert_dir.glob("*.cer"):
        clean_name = re.sub(r"[^A-Za-z0-9._-]", "_", cert_file.stem) + ".crt"
        new_path = cert_dir / clean_name
        cert_file.rename(new_path)

        with open(new_path, "r") as f:
            combined += f.read() + "\n"
        new_path.unlink()
        intel_count += 1

    # Also check for .crt files that were extracted
    for cert_file in cert_dir.glob("*.crt"):
        if cert_file.name == "intel-ca-bundle.crt":
            continue
        with open(cert_file, "r") as f:
            content = f.read()
            if content not in combined:
                combined += content + "\n"
                intel_count += 1

    with open(bundle_path, "w") as f:
        f.write(combined)

    # Cleanup zip
    zip_path.unlink(missing_ok=True)

    print(f"\nCertificate bundle created: {bundle_path}")
    print(f"  Intel certificates added: {intel_count}")
    print()
    print("Add to your shell profile:")
    print(f"  csh:  setenv REQUESTS_CA_BUNDLE {bundle_path}")
    print(f"        setenv SSL_CERT_FILE {bundle_path}")
    print(f"  bash: export REQUESTS_CA_BUNDLE={bundle_path}")
    print(f"        export SSL_CERT_FILE={bundle_path}")
    print()
    print("Or set INTEL_CERT_BUNDLE and the agent will find it:")
    print(f"  csh:  setenv INTEL_CERT_BUNDLE {bundle_path}")


if __name__ == "__main__":
    main()
