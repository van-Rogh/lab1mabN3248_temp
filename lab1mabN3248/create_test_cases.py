import argparse
import os
from secrets import token_bytes
from random import randrange

_MIN_BYTES_AMOUNT = 1
_MAX_BYTES_AMOUNT = 100


def generate_bytes_sequence(max: int) -> bytes:
    bytes_amount = randrange(_MIN_BYTES_AMOUNT, max)
    return token_bytes(bytes_amount).replace(b"\x00", b"")


def obtain_frequent_byte(bytes_sequence: bytes) -> bytes:
    is_exclusive = True
    max_frequency = 0
    frequent = 0
    for byte in bytes_sequence:
        frequency = bytes_sequence.count(byte)
        if frequency == max_frequency and byte != frequent:
            is_exclusive = False
            continue
        if frequency > max_frequency:
            max_frequency = frequency
            frequent = byte

            is_exclusive = True
    if is_exclusive:
        return frequent
    return 0


def clear_testcases() -> None:
    dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "examples")
    for root, dirs, files in os.walk(dir):
        for file in files:
            if "testcase" in file:
                path = os.path.join(root, file)
                os.remove(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create testcases for lib1mabN3248.so")
    parser.add_argument("amount", type=int, help="Amount of testcases to create")
    parser.add_argument(
        "-l",
        "--max-length",
        nargs="?",
        default=_MAX_BYTES_AMOUNT,
        type=int,
        help="Max length of byte sequence",
    )
    args = parser.parse_args()
    clear_testcases()
    for i in range(args.amount):
        with open(f"./examples/testcase_{i}", "wb") as file:
            while not obtain_frequent_byte(
                sequence := generate_bytes_sequence(args.max_length)
            ):
                pass
            file.write(sequence)
            os.rename(
                f"./examples/testcase_{i}",
                f"./examples/testcase_{i}_{obtain_frequent_byte(sequence)}",
            )


if __name__ == "__main__":
    main()
