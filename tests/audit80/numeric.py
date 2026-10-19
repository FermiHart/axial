#!/usr/bin/env python3
"""Independent oracle: full Python integers, scaled division + ties to even.

No float(), decimal-to-float libc conversion, C implementation, or formatter
round trip is used to calculate expected IEEE bits. The oracle does not use
the production binary search or its bounded-prefix/sticky representation.
"""
from fractions import Fraction
from pathlib import Path
import random
import re
import subprocess
import sys

INF = 0x7FF0000000000000
SENTINEL = 0xDEADBEEF12345678
DECIMAL = re.compile(r"[0-9][0-9_]*\.[0-9][0-9_]*\Z")


def round_even(numerator, denominator):
    quotient, remainder = divmod(numerator, denominator)
    twice = 2 * remainder
    return quotient + (twice > denominator or (twice == denominator and quotient % 2))


def expected(text):
    if not DECIMAL.fullmatch(text):
        return 1, SENTINEL
    whole, fractional = text.replace("_", "").split(".")
    numerator = int(whole + fractional)
    denominator = 10 ** len(fractional)
    if not numerator:
        return 0, 0
    exponent = numerator.bit_length() - denominator.bit_length()
    if exponent >= 0:
        if numerator < denominator << exponent:
            exponent -= 1
    elif numerator << -exponent < denominator:
        exponent -= 1
    if exponent > 1023:
        return 2, SENTINEL
    shift = 52 - max(exponent, -1022)
    if shift >= 0:
        significand = round_even(numerator << shift, denominator)
    else:
        significand = round_even(numerator, denominator << -shift)
    if significand >= 1 << 53:
        significand >>= 1
        exponent += 1
    if exponent > 1023:
        return 2, SENTINEL
    if exponent < -1022:
        return 0, significand
    return 0, ((exponent + 1023) << 52) + significand - (1 << 52)


def dyadic_text(numerator, exponent):
    """Exact finite decimal of numerator * 2**exponent, no exponent syntax."""
    if exponent >= 0:
        return str(numerator << exponent) + ".0"
    decimal = str(numerator * 5 ** -exponent)
    point = len(decimal) + exponent
    if point <= 0:
        return "0." + "0" * -point + decimal
    return decimal[:point] + "." + decimal[point:]


def boundary_text(lower):
    field, fraction = lower >> 52, lower & ((1 << 52) - 1)
    mantissa = fraction | ((1 << 52) if field else 0)
    exponent = field - 1076 if field else -1075
    return dyadic_text(2 * mantissa + 1, exponent)


def fixtures():
    values = ["0.0", "00.000_0", "0.1", "0.3", "0.7", "1.25", "1_.0_",
              "9007199254740993.0", "18446744073709551616.0",
              "1.00000000000000011102230246251565404236316680908203125",
              "2.2250738585072012" + "0" * 300,
              "0." + "0" * 4000 + "1", "9" * 4000 + ".0"]
    values += ["", "1", ".1", "1.", "1._1", "_1.0", "1.0e1", "1.0f",
               "-1.0", "+1.0", "inf", "nan", "1,0", "1.0.0", "1.0 "]
    lowers = [0, 1, 2, 3, 0x000FFFFFFFFFFFFE, 0x000FFFFFFFFFFFFF,
              0x0010000000000000, 0x3FEFFFFFFFFFFFFF, 0x3FF0000000000000,
              0x3FF0000000000001, 0x7FEFFFFFFFFFFFFE, 0x7FEFFFFFFFFFFFFF]
    rng = random.Random(0xA8063)
    lowers += [rng.randrange(INF) for _ in range(180)]
    for lower in lowers:
        midpoint = boundary_text(lower)
        values += [midpoint, midpoint + "0" * 900, midpoint + "0" * 900 + "1"]
        # A decimal just below the exact midpoint; all arithmetic stays exact.
        whole, fractional = midpoint.split(".")
        n = int(whole + fractional)
        below = str(n * 10 - 1).zfill(len(fractional) + 2)
        values.append(below[:-len(fractional) - 1] + "." + below[-len(fractional) - 1:])
    for _ in range(1200):
        count = rng.choice([1, 2, 17, 19, 40, 309, 800, 801, 1500])
        digits = "".join(str(rng.randrange(10)) for _ in range(count))
        point = rng.randrange(-340, 320)
        if point <= 0:
            value = "0." + "0" * -point + digits
        elif point >= count:
            value = digits + "0" * (point - count) + ".0"
        else:
            value = digits[:point] + "." + digits[point:]
        values.append(value)
    return values


def check_reader(driver):
    values = fixtures()
    run = subprocess.run([str(driver)], input="\n".join(values) + "\n",
                         text=True, capture_output=True, check=True)
    actual = run.stdout.splitlines()
    assert len(actual) == len(values), (len(actual), len(values), run.stderr)
    for index, (source, result) in enumerate(zip(values, actual)):
        status, bits = result.split()
        wanted = expected(source)
        got = int(status), int(bits, 16)
        assert got == wanted, (index, source, got, wanted)
    print(f"numeric W63: PASS ({len(values)} exact-integer reader fixtures)")


if __name__ == "__main__":
    check_reader(Path(sys.argv[1]).resolve())
