from decimal import Decimal
from fractions import Fraction
from pathlib import Path
import math
import os
import random
import struct
import subprocess
import sys

sys.set_int_max_str_digits(0)
INF = 0x7ff0000000000000
MAX = INF - 1
SENTINEL = 0xdeadbeef12345678
rng = random.Random(0x800C2055)

def value(bits):
    return struct.unpack('>d', bits.to_bytes(8, 'big'))[0]

def bits(number):
    return int.from_bytes(struct.pack('>d', number), 'big')

def rational(bits_value):
    # Independently decode through Python's exact binary64 integer ratio.
    if bits_value == INF:
        return Fraction(1 << 1024)
    numerator, denominator = value(bits_value).as_integer_ratio()
    return Fraction(numerator, denominator)

def plain(number):
    denominator = number.denominator
    twos = (denominator & -denominator).bit_length() - 1
    denominator >>= twos
    fives = 0
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    assert denominator == 1
    scale = max(twos, fives)
    coefficient = number.numerator * 2 ** (scale - twos) * 5 ** (scale - fives)
    text = str(coefficient).zfill(scale + 1)
    if not scale:
        return text + '.0'
    return text[:-scale] + '.' + text[-scale:]

def point(text):
    whole, fractional = text.split('.')
    if whole.strip('0'):
        return len(whole.lstrip('0'))
    return -(len(fractional) - len(fractional.lstrip('0')))

def builtin_parse(text):
    converted = float(text.replace('_', ''))
    return (2, SENTINEL) if math.isinf(converted) else (0, bits(converted))

commands = []
expected = []
labels = []
boundaries = {0, 1, 2, 3, (1 << 52)-2, (1 << 52)-1,
              1 << 52, (2 << 52)-2, (2 << 52)-1,
              2 << 52, (3 << 52)-1,
              bits(1.0)-1, bits(1.0), bits(1.0)+1, MAX-1, MAX}
boundaries.update((1 << 52) | rng.getrandbits(52) for _ in range(12))
boundaries.update(rng.getrandbits(52) for _ in range(5))
longest_significand = 0

for lower in sorted(boundaries):
    midpoint = (rational(lower) + rational(lower + 1)) / 2
    original = plain(midpoint)
    significance = len(original.replace('.', '').lstrip('0').rstrip('0'))
    longest_significand = max(longest_significand, significance)
    for retained in [799, 800, 801, 1025, 2048]:
        power = point(original) - retained
        quantum = Fraction(10 ** power) if power >= 0 else Fraction(1, 10 ** -power)
        assert quantum < (rational(lower + 1) - rational(lower)) / 4
        for direction in [-1, 0, 1]:
            source = plain(midpoint + direction * quantum)
            if direction == 0:
                # Keep exactly the same rational, with a long all-zero suffix.
                source += '0' * retained
            wanted_bits = lower if direction < 0 else lower + 1
            if direction == 0:
                wanted_bits = lower + (lower & 1)
            wanted = (2, SENTINEL) if wanted_bits == INF else (0, wanted_bits)
            assert builtin_parse(source) == wanted, (hex(lower), retained, direction)
            # Underscores must not consume significant-prefix positions.
            if retained == 801:
                whole, frac = source.split('.')
                source = '_'.join(whole) + '.' + '_'.join(frac) + '_'
            commands.append('P ' + source)
            expected.append(wanted)
            labels.append(('midpoint', hex(lower), retained, direction))

# Decimal decade crossings are distinct from the existing binary-binade sweep.
formatter_values = {0, 1 << 63, 1, MAX, MAX | (1 << 63)}
for decade in range(-323, 309):
    center = bits(float('1e' + str(decade)))
    for displacement in [-2, -1, 0, 1, 2]:
        if 0 <= center + displacement < INF:
            formatter_values.add(center + displacement)
    if decade % 41 == 0:
        formatter_values.add(center | (1 << 63))
for entry in sorted(formatter_values):
    expected_text = format(Decimal(repr(value(entry))), 'f')
    if '.' not in expected_text:
        expected_text += '.0'
    commands.append(f'F {entry:016x}')
    expected.append((0, expected_text))
    labels.append(('decimal-decade', hex(entry)))

env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
result = subprocess.run(['/tmp/axial-numeric-crossreview/probe'], input='\n'.join(commands)+'\n',
                        text=True, capture_output=True, env=env, timeout=60)
print(result.stderr.strip())
if result.returncode:
    raise SystemExit(result.returncode)
answers = result.stdout.splitlines()
assert len(answers) == len(expected), (len(answers), len(expected))
for command, answer, wanted, label in zip(commands, answers, expected, labels):
    status, payload = answer.split(' ', 1)
    actual = (int(status), int(payload, 16) if command[0] == 'P' else payload)
    if actual != wanted:
        Path('/tmp/axial-numeric-crossreview/counterexample.txt').write_text(command+'\n')
        raise AssertionError((label, actual, wanted))
print(f'cross-review PASS: {len(boundaries)} exact boundaries x 15 variants = {len(boundaries)*15} reader probes; '
      f'{len(formatter_values)} decimal-decade formatter probes; longest exact boundary significand={longest_significand}; '
      'independent CPython conversion/repr cross-check; four fenv modes; ASan/UBSan and canaries')
