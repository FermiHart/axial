"""Byte-domain regression for GCC portability fix, no ABI changes."""
import ctypes, hashlib, pathlib, subprocess, tempfile
root = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    lib = pathlib.Path(temp) / 'canon.so'
    subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                    '-D_POSIX_C_SOURCE=200809L', '-D_DARWIN_C_SOURCE', '-I'+str(root/'src'), '-I'+str(root/'include'), '-I'+str(root/'vendor'),
                    *[str(p) for p in (root/'src').glob('*.c') if p.name not in ('axi_main.c','axi_dossier_main.c')],
                    str(root/'vendor/ed25519.c'), '-lm', '-o', str(lib)], check=True)
    fn = ctypes.CDLL(str(lib)).axi_trust_canon_v1_root
    fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    for seed in range(256):
        page = bytes((i * 17 + seed) & 255 for i in range(4096))
        inp = ctypes.create_string_buffer(page)
        out = ctypes.create_string_buffer(32)
        assert fn(inp, out, 4096) == 0
        assert out.raw == hashlib.sha256(b'SINGUOS-TRUST-v1\0' + page[:1152]).digest()
    assert fn(None, out, 4096) == -1
    assert fn(inp, out, 4095) == -1
print('trust canon: 256 SHA256 reference comparisons and refusals PASS')
