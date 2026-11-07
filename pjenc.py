#!/usr/bin/env python3
import abc
import argparse
import dataclasses
import fileinput
import getpass
import json
import logging
import os
import pathlib
import subprocess
import sys

main_logger = logging.getLogger(__name__)

PRIVATE_KEYFILE_NAME = "pass.key"
PUBLIC_KEYFILE_NAME = "public_key"


class Cipher(abc.ABC):
    """Represents the algorithm to encrypt and decrypt files"""

    @abc.abstractmethod
    def __init__(self, dir_path: str, openssl_path: str, must_exist: bool):
        """Initialise the cipher and its relavant keys"""

    @abc.abstractmethod
    def encrypt(self, input_file: str, output_file: str):
        """Encrypt the contents of an input file, into a given output file"""

    @abc.abstractmethod
    def decrypt(self, input_file: str, output_file: str):
        """Decrypt the contents of an input file, into a given output file"""


# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------
def run_cmd(cmd, input_data=None):
    """Run a shell command and raise on error."""
    result = subprocess.run(
        cmd,
        input=input_data,
        capture_output=True,
        check=False,
        text=False,
    )
    if result.returncode != 0:
        main_logger.error(result.stderr.decode() + f"\n* obtained frommcommand {cmd}")
        sys.exit(1)
    return result.stdout


class SymmetricCipher(Cipher):
    """A Symmetric cipher, implemented with aes-256-cbc algorithm"""

    keyfile_path: str
    """The file to the AES key"""

    openssl_path: str
    """The path/command for openssl"""

    def __init__(self, dir_path: str, openssl_path: str, must_exist: bool):
        os.makedirs(dir_path, exist_ok=True)
        self.openssl_path = openssl_path
        self.keyfile_path = dir_path / PRIVATE_KEYFILE_NAME
        if os.path.exists(self.keyfile_path) == False:
            if must_exist:
                main_logger.error("key files does not exist")
                sys.exit(2)
            run_cmd(
                [
                    f"{self.openssl_path}",
                    "rand",
                    f"-out={self.keyfile_path}",
                    "64",
                ]
            )

    def encrypt(self, input_file: str, output_file: str):
        return run_cmd(
            [
                f"{self.openssl_path}",
                "enc",
                "-e",
                "-a",
                "-aes-256-cbc",
                f"-in={input_file}",
                f"-out={output_file}",
                "-pbkdf2",
                f"-kfile={self.keyfile_path}",
            ]
        )

    def decrypt(self, input_file: str, output_file: str):
        return run_cmd(
            [
                f"{self.openssl_path}",
                "enc",
                "-d",
                "-a",
                "-aes-256-cbc",
                f"-in={input_file}",
                f"-out={output_file}",
                "-pbkdf2",
                f"-kfile={self.keyfile_path}",
            ]
        )


class AsymmetricCipher(Cipher):
    """An asymmetric cipher, implemented with ED25519 algorithm"""

    public_key_path: str
    """The path to the public key file"""

    private_key_path: str
    """The path to a private key file"""

    openssl_path: str
    """The path/command for openssl"""

    def __init__(self, dir_path: str, openssl_path: str, must_exist: bool):
        os.makedirs(dir_path, exist_ok=True)
        self.openssl_path = openssl_path
        self.public_key_path = dir_path / PUBLIC_KEYFILE_NAME
        self.private_key_path = dir_path / PRIVATE_KEYFILE_NAME
        if (
            must_exist
            and (
                os.path.exists(self.public_key_path)
                and os.path.exists(self.private_key_path)
            )
            == False
        ):
            main_logger.error("could not find assymetric key pair")
            sys.exit(3)
        elif must_exist == False and os.path.exists(self.public_key_path) == False:
            run_cmd(
                [
                    f"{self.openssl_path}",
                    "genpkey",
                    "-algorithm=ED25519",
                    f"-out={self.private_key_path}",
                    f"-outpubkey={self.public_key_path}",
                ]
            )

    def encrypt(self, input_file: str, output_file: str):
        return run_cmd(
            [
                f"{self.openssl_path}",
                "enc",
                "-e",
                "-a",
                f"-in={input_file}",
                f"-out={output_file}",
                "-pbkdf2",
                f"-kfile={self.private_key_path}",
            ]
        )

    def decrypt(self, input_file: str, output_file: str):
        return run_cmd(
            [
                f"{self.openssl_path}",
                "enc",
                "-d",
                "-a",
                f"-in={input_file}",
                f"-out={output_file}",
                "-pbkdf2",
                f"-kfile={self.public_key_path}",
            ]
        )


@dataclasses.dataclass(init=True)
class ConfigData:
    """Represents the config file"""

    symmetric_cipher: bool
    """If true, a symmetric cipher will be used, otherwise an assymteric cipher will be used"""

    editor: str
    """The command for the editor to edit the files"""

    openssl_path: str
    """The command/path for openssl"""


# The name of the config directory
CONFIG_DIR_NAME = ".pjconfig"

# The name of the config file
CONFIG_FILE_NAME = "config.json"


def setup_main(args: argparse.ArgumentParser):
    main_logger.debug("Starting setup phase")
    cwd = pathlib.Path(__file__).parent.resolve()
    config_dir = cwd / CONFIG_DIR_NAME
    config_path = config_dir / CONFIG_FILE_NAME
    if os.path.exists(config_path):
        main_logger.error("configuration already exists")
        sys.exit(8)
    main_logger.debug(f"Found path of `config_dir`={config_dir}")
    sym_cipher = True
    expect_existing_cipher = False
    if args.key == "use-existing":
        expect_existing_cipher = True
        main_logger.debug("Checking config directory for existing keys")
        if os.path.exists(config_dir) and os.path.exists(
            config_dir / PUBLIC_KEYFILE_NAME
        ):
            if os.path.exists(config_dir / PRIVATE_KEYFILE_NAME):
                main_logger.info("Found public-private key pairs within setup")
                sym_cipher = False
            else:
                main_logger.info("Found keys for symmetric cipher within setup")
        else:
            main_logger.error(
                "Used --key=use-existing, but no existing key files found"
            )
            sys.exit(6)
    elif args.key == "generate-asym":
        sym_cipher = False
        main_logger.debug(
            "The program will generate a pair of asymmetric keys for the cipher"
        )
    elif args.key == "enter-sym":
        os.makedirs(config_dir, exist_ok=True)
        key = getpass.getpass("Enter the key for the symmetric cipher: ", echo_char="*")
        with open(config_dir / PRIVATE_KEYFILE_NAME, "w") as keyfile:
            keyfile.write(key[:64])
        expect_existing_cipher = True
        main_logger.debug("Written the keyfile to config")
    config_dc = ConfigData(sym_cipher, args.editor, args.openssl_path)
    config_map = dataclasses.asdict(config_dc)
    os.makedirs(config_dir, exist_ok=True)
    with open(config_path, "w") as config_file:
        json.dump(config_map, config_file)
    main_logger.debug("Written the config data successfully")
    if config_dc.symmetric_cipher:
        SymmetricCipher(config_dir, config_dc.openssl_path, expect_existing_cipher)
    else:
        AsymmetricCipher(config_dir, config_dc.openssl_path, expect_existing_cipher)
    main_logger.info("Setup completed")


@dataclasses.dataclass
class PjencContext:
    cwd: str
    conf_dir: str
    config: ConfigData
    cipher: Cipher


def load_context() -> PjencContext:
    main_logger.debug("Preparing to load context")
    cwd = pathlib.Path(__file__).parent.resolve()
    config_dir = cwd / CONFIG_DIR_NAME
    config_file_path = config_dir / CONFIG_FILE_NAME
    if (os.path.exists(config_dir) and os.path.exists(config_file_path)) == False:
        main_logger.error("Could not load config files")
        sys.exit(4)
    cipher: Cipher
    with open(config_file_path, "r") as config_file:
        data = json.load(config_file)
        conf = ConfigData(
            data["symmetric_cipher"],
            data["editor"],
            data["openssl_path"],
        )
        if conf.symmetric_cipher:
            cipher = SymmetricCipher(config_dir, conf.openssl_path, True)
        else:
            cipher = AsymmetricCipher(config_dir, conf.openssl_path, True)
    main_logger.debug("loaded context for encryption")
    return PjencContext(
        cwd,
        config_dir,
        conf,
        cipher,
    )


def open_main(args: argparse.ArgumentParser):
    context = load_context()
    target_file = args.target
    temp_file = context.conf_dir / "temp"
    if os.path.exists(target_file):
        main_logger.debug("Decrypting data as a temporary file")
        context.cipher.decrypt(target_file, temp_file)
    else:
        main_logger.debug("Opening new file as temporary")
    subprocess.run(
        [
            context.config.editor,
            temp_file,
        ],
        check=True,
    )
    main_logger.debug("Now encrypting data as the target file")
    context.cipher.encrypt(temp_file, target_file)
    main_logger.debug("Deleting temporary file")
    os.remove(temp_file)


def dump_main(args: argparse.ArgumentParser):
    context = load_context()
    target_file = args.target
    temp_file = context.conf_dir / "temp"
    if target_file in ["-", "", None]:
        main_logger.debug("Obtaining file input...")
        with open(temp_file, "w") as temp:
            temp.writelines(sys.stdin)
        main_logger.debug("Done writing contents to file")
        temp_output = context.conf_dir / "temp-output"
        context.cipher.decrypt(temp_file, temp_output)
        main_logger.debug("Decryption complete!")
        with open(temp_output) as temp:
            print(temp.read())
        os.remove(temp_file)
        os.remove(temp_output)
    elif os.path.exists(target_file):
        main_logger.debug("decrypting directly from file...")
        context.cipher.decrypt(target_file, temp_file)
        with open(temp_file) as temp:
            print(temp.read())
        os.remove(temp_file)
    else:
        main_logger.error(f"the specified file {target_file} is not found")
        sys.exit(9)


# ------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------
def main():
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(
        description="Secure file editor – encrypt/decrypt on‑the‑fly.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # setup ---------------------------------------------------
    p_setup = sub.add_parser(
        "setup",
        help="initialise temporary folder & key",
        aliases=["s"],
    )
    p_setup.add_argument(
        "-k",
        "--key",
        type=str,
        default="generate-sym",
        help="specifies the cipher to generate for this",
        choices=["generate-sym", "enter-sym", "generate-asym", "use-existing"],
    )
    p_setup.add_argument(
        "-e",
        "--editor",
        help="text editor command (for eg vim or nano)",
        required=True,
    )
    p_setup.add_argument(
        "-o",
        "--openssl_path",
        type=str,
        default="openssl",
        help="The path to run openssl",
    )
    p_setup.set_defaults(func=setup_main)

    # edit ----------------------------------------------------
    p_edit = sub.add_parser(
        "edit",
        help="edit a file in this journal",
        aliases=["e"],
    )
    p_edit.add_argument(
        "target",
        help="relative path of the encrypted file to edit",
    )
    p_edit.set_defaults(func=open_main)

    p_dump = sub.add_parser(
        "dump",
        help="dump contents of existing file or stdin",
        aliases=["d"],
    )
    p_dump.add_argument(
        "target",
        help="relative path of the encrypted file to dump",
        default="",
    )
    p_dump.set_defaults(func=dump_main)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
