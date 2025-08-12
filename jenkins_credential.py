#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Jenkins Credential Decryption Tool
==================================

A simple tool for decrypting individual Jenkins credentials using master.key,
hudson.util.Secret, and encrypted credential strings.

Author: Optimized version
License: MIT
"""

import re
import sys
import base64
import argparse
from pathlib import Path
from typing import Union
from hashlib import sha256

try:
    from Crypto.Cipher import AES
except ImportError:
    print("Error: pycryptodome is required. Install with: pip install pycryptodome")
    sys.exit(1)

MAGIC_BYTES = b"::::MAGIC::::"
AES_BLOCK_SIZE = 16

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    @classmethod
    def disable(cls):
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ''
        cls.PURPLE = cls.CYAN = cls.WHITE = cls.BOLD = cls.UNDERLINE = cls.END = ''

if not sys.stdout.isatty():
    Colors.disable()

class JenkinsDecryptionError(Exception):
    """Custom exception for Jenkins decryption errors"""
    pass

class JenkinsCredentialDecryptor:
    """Jenkins credential decryption handler"""
    
    def __init__(self, master_key_path: Union[str, Path], hudson_secret_path: Union[str, Path]):
        self.master_key_path = Path(master_key_path)
        self.hudson_secret_path = Path(hudson_secret_path)
        self._secret_key = None
        
    def _load_secret_key(self) -> bytes:
        """Load and derive the AES secret key from Jenkins files"""
        if self._secret_key is not None:
            return self._secret_key
            
        try:
            # Read master key
            if not self.master_key_path.exists():
                raise JenkinsDecryptionError(f"Master key file not found: {self.master_key_path}")
            master_key = self.master_key_path.read_bytes()
            
            # Read hudson secret
            if not self.hudson_secret_path.exists():
                raise JenkinsDecryptionError(f"Hudson secret file not found: {self.hudson_secret_path}")
            hudson_secret = self.hudson_secret_path.read_bytes()
            
            # Derive encryption key
            hashed_master = sha256(master_key).digest()[:AES_BLOCK_SIZE]
            cipher = AES.new(hashed_master, AES.MODE_ECB)
            decrypted_hudson = cipher.decrypt(hudson_secret)
            
            # Extract the actual secret (first 16 bytes after removing last 16)
            self._secret_key = decrypted_hudson[:-AES_BLOCK_SIZE][:AES_BLOCK_SIZE]
            
            return self._secret_key
            
        except Exception as e:
            raise JenkinsDecryptionError(f"Failed to load secret key: {str(e)}")
    
    def _decrypt_new_format(self, secret_key: bytes, payload: bytes) -> str:
        """Decrypt new format Jenkins credentials (payload version 1)"""
        try:
            data = payload[1:]  # Skip version byte
            
            # Extract IV length
            if len(data) < 8:
                raise JenkinsDecryptionError("Invalid payload: too short for new format")
                
            iv_length = int.from_bytes(data[:4], byteorder='big')
            data = data[8:]  # Skip IV length and next 4 bytes
            
            if len(data) < iv_length:
                raise JenkinsDecryptionError(f"Invalid payload: expected IV length {iv_length}, got {len(data)}")
            
            # Extract IV and encrypted data
            iv = data[:iv_length]
            encrypted_data = data[iv_length:]
            
            if len(encrypted_data) == 0:
                raise JenkinsDecryptionError("No encrypted data found")
            
            # Decrypt using AES-CBC
            cipher = AES.new(secret_key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_data)
            
            # Handle PKCS7 padding
            if len(decrypted) < AES_BLOCK_SIZE:
                raise JenkinsDecryptionError("Decrypted data too short")
                
            padding_length = decrypted[-1]
            if padding_length > AES_BLOCK_SIZE or padding_length == 0:
                password = decrypted
            else:
                password = decrypted[:-padding_length]
            
            return password.decode('utf-8', errors='replace')
            
        except UnicodeDecodeError as e:
            raise JenkinsDecryptionError(f"Failed to decode password as UTF-8: {str(e)}")
        except Exception as e:
            raise JenkinsDecryptionError(f"Failed to decrypt new format: {str(e)}")
    
    def _decrypt_old_format(self, secret_key: bytes, payload: bytes) -> str:
        """Decrypt old format Jenkins credentials (payload version 0)"""
        try:
            # Decrypt using AES-ECB
            cipher = AES.new(secret_key, AES.MODE_ECB)
            decrypted = cipher.decrypt(payload)
            
            # Check for magic bytes
            if MAGIC_BYTES not in decrypted:
                raise JenkinsDecryptionError("Magic bytes not found in decrypted data")
            
            # Extract password before magic bytes
            magic_pattern = re.escape(MAGIC_BYTES.decode('latin-1'))
            matches = re.findall(f'(.*)' + magic_pattern, decrypted.decode('latin-1'))
            
            if not matches:
                raise JenkinsDecryptionError("Failed to extract password from decrypted data")
            
            password = matches[0].encode('latin-1').decode('utf-8', errors='replace')
            return password
            
        except Exception as e:
            raise JenkinsDecryptionError(f"Failed to decrypt old format: {str(e)}")
    
    def decrypt_credential(self, encrypted_credential: str) -> str:
        """Decrypt a Jenkins credential string"""
        try:
            # Clean input (remove whitespace and braces if present)
            credential = encrypted_credential.strip()
            if credential.startswith('{') and credential.endswith('}'):
                credential = credential[1:-1]
            
            # Decode base64
            try:
                payload = base64.b64decode(credential)
            except Exception as e:
                raise JenkinsDecryptionError(f"Invalid base64 credential: {str(e)}")
            
            if len(payload) == 0:
                raise JenkinsDecryptionError("Empty payload after base64 decode")
            
            # Load secret key
            secret_key = self._load_secret_key()
            
            # Determine format and decrypt
            payload_version = payload[0]
            
            if payload_version == 1:
                return self._decrypt_new_format(secret_key, payload)
            else:
                return self._decrypt_old_format(secret_key, payload)
                
        except JenkinsDecryptionError:
            raise
        except Exception as e:
            raise JenkinsDecryptionError(f"Unexpected error during decryption: {str(e)}")


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="Decrypt Jenkins credentials using master.key and hudson.util.Secret",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s master.key hudson.util.Secret "AQAAABAAAAAgM2fPIY5jN..."
  %(prog)s /path/to/master.key /path/to/hudson.util.Secret "{AQAAABAAAAAgM2fPIY5jN...}"
  %(prog)s secrets/master.key secrets/hudson.util.Secret credential.txt

Common file locations:
  $JENKINS_HOME/secrets/master.key
  $JENKINS_HOME/secrets/hudson.util.Secret
        """
    )
    
    parser.add_argument('master_key', help='Path to Jenkins master.key file')
    parser.add_argument('hudson_secret', help='Path to Jenkins hudson.util.Secret file')
    parser.add_argument('credential', help='Encrypted credential string (base64) or path to file containing it')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed information')
    parser.add_argument('--version', action='version', version='Jenkins Credential Decryptor v2.0')
    
    return parser


def print_banner():
    """Print a fancy banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
     ██╗███████╗███╗   ██╗██╗  ██╗██╗███╗   ██╗███████╗
     ██║██╔════╝████╗  ██║██║ ██╔╝██║████╗  ██║██╔════╝
     ██║█████╗  ██╔██╗ ██║█████╔╝ ██║██╔██╗ ██║███████╗
██   ██║██╔══╝  ██║╚██╗██║██╔═██╗ ██║██║╚██╗██║╚════██║
╚█████╔╝███████╗██║ ╚████║██║  ██╗██║██║ ╚████║███████║
 ╚════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝
{Colors.END}
{Colors.YELLOW}    🔓 Jenkins Credential Decryption Tool v2.0 🔓{Colors.END}
{Colors.PURPLE}         Optimized • Robust • Secure{Colors.END}
"""
    print(banner)

def format_output(content: str) -> str:
    """Format the decrypted content with nice styling"""
    lines = content.strip().split('\n')
    
    # Detect content type
    if content.startswith('-----BEGIN ') and content.endswith('-----'):
        content_type = "ssh_key"
    elif len(lines) == 1 and len(content) < 100:
        content_type = "password"
    elif '@' in content and len(lines) == 1:
        content_type = "email"
    else:
        content_type = "text"
    
    # Format based on type
    if content_type == "ssh_key":
        return f"""
{Colors.GREEN}{Colors.BOLD}🔑 SSH Private Key Decrypted:{Colors.END}
{Colors.CYAN}{'=' * 50}{Colors.END}
{Colors.WHITE}{content}{Colors.END}
{Colors.CYAN}{'=' * 50}{Colors.END}
{Colors.GREEN}✅ Key ready for use!{Colors.END}
"""
    elif content_type == "password":
        return f"""
{Colors.GREEN}{Colors.BOLD}🔐 Password Decrypted:{Colors.END}
{Colors.CYAN}{'─' * 30}{Colors.END}
{Colors.YELLOW}{Colors.BOLD}{content}{Colors.END}
{Colors.CYAN}{'─' * 30}{Colors.END}
{Colors.GREEN}✅ Decryption successful!{Colors.END}
"""
    elif content_type == "email":
        return f"""
{Colors.GREEN}{Colors.BOLD}📧 Email/Username Decrypted:{Colors.END}
{Colors.CYAN}{'─' * 35}{Colors.END}
{Colors.BLUE}{Colors.BOLD}{content}{Colors.END}
{Colors.CYAN}{'─' * 35}{Colors.END}
{Colors.GREEN}✅ Credential extracted!{Colors.END}
"""
    else:
        return f"""
{Colors.GREEN}{Colors.BOLD}📄 Content Decrypted:{Colors.END}
{Colors.CYAN}{'─' * 40}{Colors.END}
{Colors.WHITE}{content}{Colors.END}
{Colors.CYAN}{'─' * 40}{Colors.END}
{Colors.GREEN}✅ Decryption complete!{Colors.END}
"""

def print_error(message: str):
    """Print formatted error message"""
    print(f"\n{Colors.RED}{Colors.BOLD}❌ ERROR:{Colors.END} {Colors.RED}{message}{Colors.END}\n")

def print_success_stats(decryptor, args):
    """Print success statistics"""
    print(f"\n{Colors.GREEN}{Colors.BOLD}📊 Decryption Stats:{Colors.END}")
    print(f"{Colors.BLUE}• Master Key:{Colors.END} {args.master_key}")
    print(f"{Colors.BLUE}• Hudson Secret:{Colors.END} {args.hudson_secret}")
    print(f"{Colors.BLUE}• Input Type:{Colors.END} {'File' if Path(args.credential).exists() else 'Direct'}")
    print(f"{Colors.GREEN}• Status:{Colors.END} {Colors.GREEN}SUCCESS ✅{Colors.END}")


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Print banner for interactive mode
    if sys.stdout.isatty() and not args.verbose:
        print_banner()
    
    try:
        # Read credential
        cred_input = args.credential
        credential_path = Path(cred_input)
        if credential_path.exists():
            credential = credential_path.read_text(encoding='utf-8').strip()
        else:
            credential = cred_input.strip()
        
        # Decrypt
        decryptor = JenkinsCredentialDecryptor(args.master_key, args.hudson_secret)
        plaintext = decryptor.decrypt_credential(credential)
        
        # Output formatted result
        output = format_output(plaintext)
        print(output)
        
        if args.verbose:
            print_success_stats(decryptor, args)
        
    except JenkinsDecryptionError as e:
        print_error(str(e))
        sys.exit(2)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Operation cancelled by user{Colors.END}")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
