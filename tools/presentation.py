#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-SPL-1.0
# Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>

"""Capture real Axial commands; publish only curated presentation media."""
import argparse
from dataclasses import dataclass
import fcntl
from functools import lru_cache
import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import struct
import subprocess
import tempfile
import termios
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'website/assets'
COPYRIGHT = 'Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>'
LICENSE = 'LicenseRef-SPL-1.0'
ASSETS = ('hero-cell.svg', 'hero-cell-mobile.svg', 'axial-in-action.gif',
          'policy-in-action.gif', 'cell-contract.png', 'runtime-guards.png', 'policy.png')
BG, PANEL, TEXT, DIM = '#070a12', '#0d1220', '#f5f1df', '#8794b8'
CYAN, VIOLET, GOLD, PASS, FAIL = '#65e3ef', '#a4afff', '#ffcc66', '#65fbd2', '#ff6b8a'
PROMPT = re.compile(rb'\x1b\]777;AXI_RC=(\d+)\x07(?:\x1b\[[0-9;?]*[A-Za-z])*axi\$ ')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprint():
    files = [ROOT/'Makefile', ROOT/'LICENSE', Path(__file__), ROOT/'tools/check.sh']
    listed = subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=ROOT).decode().split('\0')
    for name in listed:
        if name.startswith(('src/','include/','vendor/','examples/','scripts/','tests/','abi/')) or name in ('tools/test-identity.sh','tools/axi-checker-identity.py'):
            path=ROOT/name
            if path.is_file():
                files.append(path)
    result = hashlib.sha256(b'axial/presentation/v1\0')
    for path in sorted(set(files)):
        data = path.read_bytes()
        result.update(str(path.relative_to(ROOT)).encode()+b'\0'+struct.pack('<Q', len(data))+data)
    return result.hexdigest()


@dataclass
class Shot:
    cells: list
    phase: str
    verdict: str
    duration: int = 90


class Terminal:
    """An actual interactive Bash PTY drives the actual compiled CLI."""
    def __init__(self, cwd, env):
        import pyte
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 26, 104, 0, 0))
        self.screen = pyte.Screen(104, 26)
        self.stream = pyte.ByteStream(self.screen)
        self.pending, self.raw, self.frames = b'', bytearray(), []
        self.phase, self.verdict, self.last = '01 / READ THE CONTRACT', 'LIVE COMMAND CAPTURE', 0
        shell_env = dict(env, PS1='axi$ ', PROMPT_COMMAND="printf '\033]777;AXI_RC=%s\007' \"$?\"",
                         TERM='xterm-256color', HISTFILE='/dev/null', LC_ALL='C.UTF-8')
        shell_env.pop('BASH_ENV', None)
        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        self.process = subprocess.Popen(['bash','--noprofile','--norc','-i'], cwd=cwd, env=shell_env,
                                        stdin=self.slave, stdout=self.slave, stderr=self.slave,
                                        preexec_fn=controlling_terminal)
        try:
            self.wait_prompt()
        except Exception:
            self.close()
            raise

    def freeze(self, duration=90):
        cells = [[(c.data, c.fg, c.bold) for c in
                  (self.screen.buffer[y][x] for x in range(104))] for y in range(26)]
        shot = Shot(cells, self.phase, self.verdict, duration)
        if self.frames and (shot.cells, shot.phase, shot.verdict) == (self.frames[-1].cells, self.frames[-1].phase, self.frames[-1].verdict):
            self.frames[-1].duration += duration
        else:
            self.frames.append(shot)
        self.last = time.monotonic()
        return shot

    def pump(self, timeout=.02):
        if select.select([self.master], [], [], timeout)[0]:
            data = os.read(self.master, 65536)
            self.raw.extend(data)
            self.pending += data
            self.stream.feed(data)
            if time.monotonic()-self.last > .085:
                self.freeze()

    def wait_prompt(self, timeout=60):
        end = time.monotonic()+timeout
        while time.monotonic() < end:
            match = PROMPT.search(self.pending)
            if match:
                output = self.pending[:match.end()]
                self.pending = self.pending[match.end():]
                return int(match[1]), output
            if self.process.poll() is not None:
                raise RuntimeError('capture shell exited unexpectedly')
            self.pump()
        raise RuntimeError(f'command did not return to its prompt: {self.pending[-400:]!r}')

    def command(self, text, code=0, contains=None, verdict='COMMAND VERIFIED'):
        self.verdict = 'EXECUTING / OUTPUT IS FROM THE REAL TOOLCHAIN'
        for byte in (text+'\n').encode():
            os.write(self.master, bytes([byte]))
            end = time.monotonic()+.016
            while time.monotonic() < end:
                self.pump(min(.01, max(0, end-time.monotonic())))
        actual, output = self.wait_prompt()
        assert actual == code, (text, actual, output[-1200:])
        assert contains is None or re.search(contains, output), (text, output)
        self.verdict = verdict
        self.freeze(1000)
        return output

    def close(self):
        if self.process.poll() is None:
            os.write(self.master, b'exit\n')
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        os.close(self.master)
        os.close(self.slave)


@lru_cache(maxsize=1)
def fonts():
    from PIL import ImageFont
    def load(style, size):
        path = subprocess.check_output(['fc-match','-f','%{file}',style],text=True)
        return ImageFont.truetype(path,size)
    return load('DejaVu Sans Mono',19), load('DejaVu Sans Mono:style=Bold',19), load('DejaVu Sans Mono',12), load('DejaVu Sans Mono:style=Bold',25)


def render(shot):
    from PIL import Image, ImageDraw
    regular, bold, small, title = fonts()
    image = Image.new('RGB',(1320,960),BG)
    draw = ImageDraw.Draw(image)
    for x in range(0,1320,32):
        draw.line((x,0,x,960),fill='#111627')
    draw.text((40,24),'FERMI HART / AXIAL / LIVE CLI',font=small,fill=CYAN)
    draw.text((40,52),shot.phase,font=title,fill=TEXT)
    draw.rounded_rectangle((28,104,1292,844),radius=16,fill=PANEL,outline='#35415b',width=2)
    for x, color in ((54,FAIL),(77,GOLD),(100,PASS)):
        draw.ellipse((x-5,122,x+5,132),fill=color)
    draw.text((136,117),'C99 TOOLCHAIN / ACTUAL SHELL SESSION / PUBLIC TEST-VECTOR KEYS',font=small,fill=DIM)
    draw.line((30,149,1290,149),fill='#293348')
    palette={'cyan':CYAN,'green':PASS,'red':FAIL,'yellow':GOLD,'blue':VIOLET,'magenta':'#d58cff'}
    for y,row in enumerate(shot.cells):
        for x,(text,fg,strong) in enumerate(row):
            if not text.strip():
                continue
            color = palette.get(fg, '#'+fg if re.fullmatch('[0-9a-fA-F]{6}',fg) else '#e7eaf4')
            draw.text((50+x*11.65,161+y*25.5),text,font=bold if strong else regular,fill=color)
    draw.text((40,868),'ASSERTED BY THE CAPTURE DRIVER',font=small,fill=DIM)
    draw.text((40,891),shot.verdict,font=bold,fill=PASS if 'VERIFIED' in shot.verdict else CYAN)
    draw.text((40,936),'REAL CLI OUTPUT / TYPING AND PAUSES PACED / LANGUAGE BETA, NOT HOST-WIDE ENFORCEMENT',font=small,fill=DIM)
    return image


def geometry(identity, passed, mobile=False):
    w,h = (640,900) if mobile else (1200,640)
    x,cx,cy,r = (40,320,424,145) if mobile else (60,939,264,177)
    svg=[f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-labelledby="title desc">',
         '<!-- '+html.escape(COPYRIGHT)+' -->','<!-- SPDX-License-Identifier: '+LICENSE+' -->',
         f'<metadata>source-id:{identity}</metadata>',
         '<title id="title">Axial: code that answers before it gets power</title>',
         '<desc id="desc">A contract cell joins types, capabilities, fuel, checked laws, signatures and replay. Decorative source-derived geometry, not a security attestation.</desc>',
         '<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#070a12"/><stop offset=".6" stop-color="#111426"/><stop offset="1" stop-color="#071c21"/></linearGradient><pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="#8794b8" stroke-opacity=".07"/></pattern></defs>',
         f'<rect x="1" y="1" width="{w-2}" height="{h-2}" rx="24" fill="url(#bg)" stroke="#35415b"/>',
         f'<rect x="1" y="1" width="{w-2}" height="{h-2}" rx="24" fill="url(#grid)"/>']
    def text(tx,ty,value,size=16,color=TEXT,weight='400',anchor='start',spacing=0):
        svg.append(f'<text x="{tx}" y="{ty}" fill="{color}" font-family="DejaVu Sans Mono,monospace" font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" letter-spacing="{spacing}">{html.escape(value)}</text>')
    text(x,58,'FERMI HART / CONTRACT GEOMETRY',12 if mobile else 15,CYAN,'700',spacing=1.4)
    text(x,151 if mobile else 166,'AXIAL',86 if mobile else 96,TEXT,'700',spacing=-3)
    text(x,193 if mobile else 217,'CODE THAT ANSWERS.',22,GOLD,'700')
    text(x,232 if mobile else 254,'BEFORE IT GETS POWER.',16,VIOLET)
    if not mobile:
        text(x,319,'Inspect the contract.',23)
        text(x,354,'Verify what you run.',23,CYAN)
        text(x,415,'AGENTS WRITE. HUMANS SET THE LIMITS.',12,DIM)
    for rad,opacity in ((r+25,'.2'),(r,'.4'),(r*.65,'.2')):
        svg.append(f'<circle cx="{cx}" cy="{cy}" r="{rad}" fill="none" stroke="{CYAN}" stroke-opacity="{opacity}"/>')
    pts=[(cx+r*math.cos(-math.pi/2+i*math.pi/3),cy+r*math.sin(-math.pi/2+i*math.pi/3)) for i in range(6)]
    for i,a in enumerate(pts):
        for j,b in enumerate(pts[i+1:],i+1):
            svg.append(f'<path d="M{a[0]:.2f},{a[1]:.2f}L{b[0]:.2f},{b[1]:.2f}" fill="none" stroke="{GOLD if (i+j)%2 else VIOLET}" stroke-opacity=".25"/>')
    for i,label in enumerate(('TYPES','CAPS','FUEL','LAWS','SIGN','REPLAY')):
        px,py=pts[i]
        svg.append(f'<circle cx="{px:.2f}" cy="{py:.2f}" r="7" fill="{CYAN}"/>')
        text(round(px),round(py-17 if i<3 else py+28),label,11,CYAN,'700','middle',1)
    seed=bytes.fromhex(identity)
    for i in range(24):
        angle=i*math.pi/12
        svg.append(f'<circle cx="{cx+(r+25)*math.cos(angle):.2f}" cy="{cy+(r+25)*math.sin(angle):.2f}" r="{2+seed[i]%3}" fill="{(CYAN,GOLD,VIOLET,"#d58cff")[seed[i]%4]}"/>')
    svg.append(f'<path d="M{cx},{cy-57}L{cx+51},{cy-27}V{cy+27}L{cx},{cy+57}L{cx-51},{cy+27}V{cy-27}Z" fill="#111b25" stroke="{GOLD}" stroke-width="1.5"/>')
    text(cx,cy-3,'CELL',19,TEXT,'700','middle')
    text(cx,cy+20,'.AXB / V7',11,GOLD,'700','middle')
    cards=[('CORE','C99',CYAN),('ARTIFACT','ED25519',GOLD),('EXECUTION','METERED FUEL',VIOLET),('CORE GOLDENS',f'{passed} / {passed}',PASS)]
    for i,(label,value,color) in enumerate(cards):
        tx=40+(i%2)*288 if mobile else 60+i*278
        ty=650+(i//2)*94 if mobile else 482
        svg.append(f'<rect x="{tx}" y="{ty}" width="{272 if mobile else 263}" height="80" rx="10" fill="#0b111e" stroke="#293348"/>')
        text(tx+16,ty+25,label,11,DIM,'700',spacing=1)
        text(tx+16,ty+56,value,18 if i==2 else 24,color,'700')
    text(40 if mobile else 60,856 if mobile else 610,'LANGUAGE BETA / SPL-1.0 / EXECUTABLE LAW CHECKS',10 if mobile else 12,DIM)
    text(40 if mobile else 1140,878 if mobile else 610,'SOURCE / '+identity[:24].upper(),10,DIM,anchor='start' if mobile else 'end')
    return '\n'.join(svg+['</svg>',''])


def capture(work):
    env=dict(os.environ,HOME=str(work/'home'),AXI_TMPDIR=str(work/'tmp'),PATH=str(ROOT/'build')+os.pathsep+os.environ['PATH'])
    (work/'home').mkdir(mode=0o700)
    gate=subprocess.run(['make','gate-fast','demo'],cwd=ROOT,env=env,capture_output=True,text=True,timeout=120)
    (work/'gate.log').write_text(gate.stdout+gate.stderr)
    assert gate.returncode==0,gate.stderr
    match=re.search(r'axial check: (\d+) PASS, 0 FAIL',gate.stdout)
    assert match,'host gate did not report success'
    author_seed=bytes(range(32))
    author_pk=bytes.fromhex('03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8')
    recorder_seed=bytes.fromhex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')
    recorder_pk=bytes.fromhex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
    for name,data in [('author.seed',author_seed),('author.pk',author_pk),('recorder.seed',recorder_seed),('recorder.pk',recorder_pk)]:
        (work/name).write_bytes(data)
    copies={'hello.axi':'examples/hello.axi','policy.axi':'examples/policy.axi','green.axs':'tests/seal/green-add2.axs',
            'red.axs':'tests/seal/red-false-law.axs','capsule.axs':'scripts/demo-supply-chain.axs','loop.axs':'tests/run/fuel-out.axs'}
    for target,source in copies.items():
        shutil.copy2(ROOT/source,work/target)
    def cli(*args):
        return subprocess.run([str(ROOT/'build/axi'),*args],cwd=work,env=env,check=True,capture_output=True,timeout=30)
    cli('seal','capsule.axs','-o','capsule.axb','--signing-key','author.seed')
    cli('asm','loop.axs','-o','loop.axb','--signing-key','author.seed')
    terminal=Terminal(work,env)
    try:
        terminal.command('axi check hello.axi',verdict='VERIFIED / GRAMMAR + FORM + TYPES ACCEPTED')
        terminal.command('axi iface policy.axi',contains=rb'cap fs.Read',verdict='VERIFIED / CAPABILITIES AND FUEL ARE VISIBLE')
        contract=terminal.freeze(1500)
        terminal.phase='02 / ONE RED LAW. NO ARTIFACT.'
        terminal.command('axi seal red.axs -o rejected.axb --signing-key author.seed',1,rb'AXI-S002', 'VERIFIED / FALSE LAW REFUSED')
        assert not (work/'rejected.axb').exists()
        terminal.phase='03 / CHECK. SEAL. VERIFY. EXECUTE.'
        terminal.command('axi seal green.axs -o green.axb --signing-key author.seed',contains=rb'checked: 1 law',verdict='VERIFIED / EXECUTED LAW PASSED')
        terminal.command('axi verify green.axb --trusted-key author.pk',contains=rb'signature-valid',verdict='VERIFIED / OPERATOR-SELECTED PRODUCER KEY')
        terminal.command('axi check-seal green.axb --trusted-key author.pk',contains=rb'checked green.axb',verdict='VERIFIED / CHECKED LAW RE-EXECUTED')
        terminal.command('axi run green.axb add2 40 --trusted-key author.pk --fuel-report',contains=rb'u64 42',verdict='VERIFIED / VALUE 42 RETURNED WITH FUEL REPORT')
        terminal.phase='04 / DECLARED DOES NOT MEAN GRANTED.'
        terminal.command('axi run capsule.axb main --trusted-key author.pk',1,rb'AXI-R007','VERIFIED / MISSING EFFECT GRANT REFUSED')
        terminal.phase='05 / REPLAY HAS ITS OWN TRUST ANCHOR.'
        terminal.command('axi run capsule.axb main --cap io.Write --trusted-key author.pk --record run.axr --recorder-key recorder.seed',contains=rb'u64 30',verdict='VERIFIED / EFFECT EXECUTED AND EPISODE RECORDED')
        replay=terminal.command('axi replay run.axr capsule.axb main --cap io.Write --trusted-key author.pk --recorder-key recorder.pk',contains=rb'u64 30',verdict='VERIFIED / BOUND REPLAY RETURNED THE SAME VALUE')
        assert b'zero-dep supply chain artifact' not in replay,'replay repeated the live output effect'
        terminal.phase='06 / REFUSAL IS A FEATURE.'
        terminal.command('axi run loop.axb main --fuel 100 --trusted-key author.pk',1,rb'AXI-R008','VERIFIED / RUNAWAY LOOP STOPPED AT THE VM FUEL LIMIT')
        good=(work/'green.axb').read_bytes()
        bad=bytearray(good);bad[-1]^=1
        (work/'tampered.axb').write_bytes(bad)
        terminal.command('cmp -l green.axb tampered.axb',1,verdict='VERIFIED / EXACTLY ONE BIT WAS CHANGED')
        terminal.command('axi verify tampered.axb --trusted-key author.pk',1,rb'AXI-B025','VERIFIED / MODIFIED ARTIFACT REFUSED')
        guards=terminal.freeze(2400)
        frames=list(terminal.frames)
        (work/'cli.raw').write_bytes(terminal.raw)
    finally:
        terminal.close()
    policy=Terminal(ROOT,env)
    try:
        policy.phase='POLICY / REAL C EMBEDDING DECISIONS'
        output=policy.command("set -o pipefail; sh scripts/jash_policy_demo.sh | sed -n '/^rm inside workspace/,$p'",contains=rb'PASS unknown builtin',verdict='VERIFIED / ALL FIVE EXAMPLE POLICY CASES MATCH')
        for label,want in [('rm inside workspace','ALLOW'),('rm outside workspace','DENY'),('export secret name','DENY'),('export safe name','ALLOW'),('unknown builtin','ALLOW')]:
            assert re.search(label.encode()+rb'\s+-> '+want.encode(),output),label
        policy_shot=policy.freeze(5000)
        policy_frames=list(policy.frames)
        (work/'policy.raw').write_bytes(policy.raw)
    finally:
        policy.close()
    return frames,policy_frames,(contract,guards,policy_shot),{
        'gate_pass':int(match[1]),'gate_fail':0,'law_refusal_no_artifact':True,
        'checked_seal_reexecuted':True,'missing_grant_refused':True,'fuel_exhaustion_refused':True,
        'tamper_refused':True,'producer_and_recorder_distinct':author_pk!=recorder_pk,
        'replay_value_matches':True,'replay_live_io_not_repeated':True,'policy_cases':5,
        'policy_api':'internal compatibility demo; not pure embed v1',
        'axi_sha256':sha(ROOT/'build/axi'),'policy_demo_sha256':sha(ROOT/'build/jash_policy_demo'),
    }


def verify():
    from PIL import Image
    identity=fingerprint();shared=None
    for name in ASSETS:
        path=OUT/name
        assert path.is_file() and path.stat().st_size<6*1048576,name
        if path.suffix=='.svg':
            source=path.read_text()
            assert f'source-id:{identity}' in source and LICENSE in source,name
            assert ET.fromstring(source).tag=='{http://www.w3.org/2000/svg}svg'
            continue
        with Image.open(path) as image:
            data=image.info['comment'].decode() if path.suffix=='.gif' else image.info['capture']
            evidence=json.loads(data)
            assert evidence['source_id']==identity and evidence['copyright']==COPYRIGHT,name
            assert evidence['license']==LICENSE and evidence['gate_fail']==0 and evidence['gate_pass']>0
            for key in ('law_refusal_no_artifact','checked_seal_reexecuted','missing_grant_refused','fuel_exhaustion_refused','tamper_refused','producer_and_recorder_distinct','replay_value_matches','replay_live_io_not_repeated'):
                assert evidence[key],(name,key)
            assert shared is None or shared==evidence,'mixed capture sessions'
            shared=evidence
            assert image.size==(1320,960)
            if path.suffix=='.gif':
                assert image.n_frames>8 and image.info.get('loop')==0
                for index in range(image.n_frames):
                    image.seek(index);image.load()
    assert sum((OUT/name).stat().st_size for name in ASSETS)<8*1048576
    print('PASS: source-bound media, real gate/CLI assertions, shared capture, decoded frames and payload budget.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='validate curated assets without executing demo commands')
    args=parser.parse_args()
    if args.check:
        verify();return
    from PIL import Image
    from PIL.PngImagePlugin import PngInfo
    os.umask(0o077)
    base=os.environ.get('TMPDIR','/tmp/opencode' if Path('/tmp/opencode').is_dir() else None)
    work=Path(tempfile.mkdtemp(prefix='axial-capture-',dir=base))
    print('Private capture workspace:',work,flush=True)
    frames,policy_frames,shots,proof=capture(work)
    identity=fingerprint()
    evidence=dict(proof,source_id=identity,copyright=COPYRIGHT,license=LICENSE,
                  method='Actual Bash PTY and compiled Axial output; typing/pauses paced; policy metadata explicitly filtered by displayed sed command; public test-vector identities only.')
    encoded=json.dumps(evidence,sort_keys=True).encode()
    OUT.mkdir(exist_ok=True)
    (OUT/ASSETS[0]).write_text(geometry(identity,proof['gate_pass']))
    (OUT/ASSETS[1]).write_text(geometry(identity,proof['gate_pass'],True))
    png=PngInfo();png.add_text('Copyright',COPYRIGHT);png.add_text('License',LICENSE);png.add_text('capture',encoded.decode())
    for name,shot in zip(ASSETS[4:],shots):
        render(shot).save(OUT/name,pnginfo=png,optimize=True)
    palette_source=Image.new('RGB',(1320,2880))
    for i,shot in enumerate(shots):
        palette_source.paste(render(shot),(0,i*960))
    palette=palette_source.quantize(colors=128)
    for name,clip in ((ASSETS[2],frames),(ASSETS[3],policy_frames)):
        images=[render(shot).quantize(palette=palette,dither=Image.Dither.NONE) for shot in clip]
        durations=[max(60,min(shot.duration,6500)) for shot in clip]
        images[0].save(OUT/name,save_all=True,append_images=images[1:],duration=durations,loop=0,optimize=True,disposal=1,comment=encoded)
        print(name,len(clip),'frames;',round(sum(durations)/1000,2),'seconds')
    for name in ASSETS:
        (OUT/name).chmod(0o644)
    verify()


if __name__=='__main__':
    main()
