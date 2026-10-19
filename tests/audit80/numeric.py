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
    # Exact short-dyadic path and adjacent refusals of that optimization:
    # all uint64 widths, rounding carry, cancellation limits and fallback.
    for width in range(1, 65):
        for offset in range(-3, 4):
            value = (1 << (width - 1)) + offset
            if 0 <= value < 1 << 64:
                values.append(str(value) + ".0")
    for exponent in [-28, -27, -22, -9, -1, 0, 1, 9, 22, 27, 28]:
        power = 5 ** abs(exponent)
        for _ in range(64):
            coefficient = rng.randrange(1, 1 << 64)
            values.append(plain_decimal(coefficient, exponent))
            if exponent < 0:
                multiple = coefficient % max(1, ((1 << 64) - 1) // power) + 1
                exact = multiple * power
                values += [plain_decimal(exact, exponent), plain_decimal(exact + 1, exponent)]
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


def binary_value(bits):
    if bits == INF:
        return Fraction(1 << 1024)  # theoretical finite successor for overflow
    field, fraction = bits >> 52, bits & ((1 << 52) - 1)
    mantissa = fraction | ((1 << 52) if field else 0)
    exponent = field - 1075 if field else -1074
    if exponent < 0:
        return Fraction(mantissa, 1 << -exponent)
    return Fraction(mantissa << exponent)


def power10(exponent):
    return Fraction(10 ** exponent) if exponent >= 0 else Fraction(1, 10 ** -exponent)


def plain_decimal(coefficient, exponent):
    while coefficient and coefficient % 10 == 0:
        coefficient //= 10
        exponent += 1
    digits = str(coefficient)
    point = len(digits) + exponent
    if point <= 0:
        return "0." + "0" * -point + digits
    if point >= len(digits):
        return digits + "0" * (point - len(digits)) + ".0"
    return digits[:point] + "." + digits[point:]


def canonical_expected(bits):
    """Independent printer oracle: enumerate legal integer interval ranges.

    This does not try the C formatter's two candidates or call any reader.
    It intersects each p-digit decimal grid with the exact rational IEEE
    rounding interval, then chooses its closest legal integer coefficient.
    """
    negative, bits = bits >> 63, bits & ((1 << 63) - 1)
    if bits >= INF:
        return 1, "unchanged"
    if not bits:
        return 0, "-0.0" if negative else "0.0"
    exact = binary_value(bits)
    lower = (binary_value(bits - 1) + exact) / 2
    upper = (binary_value(bits + 1) + exact) / 2
    inclusive = not bits % 2
    decade = len(str(exact.numerator)) - len(str(exact.denominator))
    if exact < power10(decade):
        decade -= 1
    for precision in range(1, 18):
        candidates = []
        # The interval may cross a decimal decade boundary. The adjacent
        # decades cover it even for the widest relative interval (bit 1).
        for exponent in range(decade - precision, decade - precision + 3):
            scale = power10(exponent)
            low, high = lower / scale, upper / scale
            first = (low.numerator + low.denominator - 1) // low.denominator
            last = high.numerator // high.denominator
            if not inclusive and low.denominator == 1:
                first += 1
            if not inclusive and high.denominator == 1:
                last -= 1
            first = max(first, 10 ** (precision - 1))
            last = min(last, 10 ** precision - 1)
            if first > last:
                continue
            scaled = exact / scale
            closest = min(last, max(first, round_even(scaled.numerator, scaled.denominator)))
            value = closest * scale
            candidates.append((abs(value - exact), closest % 2, value, closest, exponent))
        if candidates:
            _, _, _, coefficient, exponent = min(candidates)
            return 0, ("-" if negative else "") + plain_decimal(coefficient, exponent)
    raise AssertionError(("no decimal in 17 digits", bits))


def format_fixtures():
    values = {0, 1 << 63, INF, INF | (1 << 63), INF + 1, (1 << 64) - 1,
              0x7FF8000000000000, 0x7FEFFFFFFFFFFFFF, 0x7FEFFFFFFFFFFFFE}
    for field in range(1, 2047):
        power = field << 52
        values.update([power - 1, power, power + 1])
    for bit in range(53):
        power = 1 << bit
        values.update([power - 1, power, power + 1])
    values.update(range(32))
    rng = random.Random(0xA8065)
    for _ in range(2000):
        values.add(rng.randrange(INF) | (rng.randrange(2) << 63))
    return sorted(values)


def check_formatter(driver):
    values = format_fixtures()
    run = subprocess.run([str(driver), "format"],
                         input="".join(f"{bits:016x}\n" for bits in values),
                         text=True, capture_output=True, check=True)
    actual = run.stdout.splitlines()
    assert len(actual) == len(values), (len(actual), len(values), run.stderr)
    reparsed = []
    reparsed_bits = []
    for bits, result in zip(values, actual):
        status, text = result.split()
        wanted = canonical_expected(bits)
        assert (int(status), text) == wanted, (f"{bits:016x}", status, text, wanted)
        if not int(status):
            decimal = text.removeprefix("-")
            assert expected(decimal) == (0, bits & ((1 << 63) - 1)), (bits, text)
            reparsed.append(decimal)
            reparsed_bits.append(bits & ((1 << 63) - 1))
    run = subprocess.run([str(driver)], input="\n".join(reparsed) + "\n",
                         text=True, capture_output=True, check=True)
    rows = run.stdout.splitlines()
    assert len(rows) == len(reparsed_bits)
    for bits, result in zip(reparsed_bits, rows):
        assert result == f"0 {bits:016x}", (bits, result)
    print(f"numeric W65: PASS ({len(values)} rational-interval canonical fixtures and exact round trips)")


if __name__ == "__main__":
    driver = Path(sys.argv[1]).resolve()
    group = sys.argv[2] if len(sys.argv) > 2 else "all"
    if group in ("reader", "all"):
        check_reader(driver)
    if group in ("format", "all"):
        check_formatter(driver)
