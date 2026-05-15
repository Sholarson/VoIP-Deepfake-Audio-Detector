import subprocess
import time
import re
import struct
import os
from collections import Counter
import requests

# =========================================================
# CONFIGURATION
# =========================================================

TSHARK_PATH = "tshark"
INTERFACE = "wlp193s0"
CAPTURE_FILE = "capture.pcap"
CAPTURE_DURATION = 15
OPUS_PAYLOAD_TYPE = 96

# =========================================================
# STEP 1 - AUTOMATICALLY GET LOCAL IP
# =========================================================

print("=" * 60)
print("DETECTING LOCAL IP ADDRESS")
print("=" * 60)

ip_output = subprocess.check_output(["ip", "addr", "show", INTERFACE]).decode()
match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ip_output)

if not match:
    print(f"Could not detect IP for interface: {INTERFACE}")
    exit()

LOCAL_IP = match.group(1)
print(f"Detected Local IP: {LOCAL_IP}")

# =========================================================
# STEP 2 - START PACKET CAPTURE
# =========================================================

print("\n" + "=" * 60)
print("REMOTE RTP AUDIO EXTRACTOR - OPUS CODEC")
print("=" * 60)

print("\nStarting packet capture...")

capture_process = subprocess.Popen([
    TSHARK_PATH,
    "-i", INTERFACE,
    "-f", "udp",
    "-w", CAPTURE_FILE
])

print("\nNOW:")
print("1. Make SIP call")
print("2. Talk for some seconds")
print("3. Disconnect call")
print(f"\nCapturing for {CAPTURE_DURATION} seconds...\n")

time.sleep(CAPTURE_DURATION)
capture_process.terminate()
print("Capture complete.")

# =========================================================
# STEP 3 - FIND ONLY INCOMING RTP STREAMS (OPUS PT)
# =========================================================

print("\nDetecting incoming Opus RTP streams...")

result = subprocess.check_output([
    TSHARK_PATH,
    "-r", CAPTURE_FILE,
    "-Y", f"rtp && ip.dst == {LOCAL_IP} && rtp.p_type == {OPUS_PAYLOAD_TYPE}",
    "-T", "fields",
    "-e", "rtp.ssrc"
]).decode()

ssrcs = [line.strip() for line in result.splitlines() if line.strip()]
counter = Counter(ssrcs)

if not counter:
    print("\nNo incoming Opus RTP streams found.")
    print("Tip: Check OPUS_PAYLOAD_TYPE. Run this to see what PTs are in the capture:")
    print(f"  tshark -r {CAPTURE_FILE} -Y rtp -T fields -e rtp.p_type | sort | uniq -c")
    exit()

print("\nIncoming Opus RTP streams:\n")
for i, ssrc in enumerate(counter.keys(), start=1):
    print(f"{i}. {ssrc} -> {counter[ssrc]} packets")

# =========================================================
# STEP 4 - SELECT MOST ACTIVE REMOTE STREAM
# =========================================================

selected_ssrc = max(counter, key=counter.get)
print(f"\nSelected remote stream: {selected_ssrc}")

# =========================================================
# STEP 5 - EXTRACT RTP PAYLOADS
# =========================================================

print("\nExtracting remote Opus audio payloads...")

result = subprocess.check_output([
    TSHARK_PATH,
    "-r", CAPTURE_FILE,
    "-Y", f"rtp.ssrc == {selected_ssrc} && ip.dst == {LOCAL_IP} && rtp.p_type == {OPUS_PAYLOAD_TYPE}",
    "-T", "fields",
    "-e", "rtp.seq",
    "-e", "rtp.timestamp",
    "-e", "rtp.payload",
    "-E", "separator=\t"
]).decode()

packets = []
for line in result.splitlines():
    parts = line.strip().split("\t")
    if len(parts) != 3:
        continue
    seq, ts, payload = parts
    if not payload:
        continue
    try:
        frame = bytes.fromhex(payload.replace(":", ""))
        packets.append((int(seq), int(ts), frame))
    except:
        continue

# =========================================================
# STEP 6 - SORT BY SEQUENCE NUMBER
# =========================================================

packets.sort(key=lambda x: x[0])
print(f"Packets extracted: {len(packets)}")

if not packets:
    print("No packets to process.")
    exit()

# =========================================================
# STEP 7 - BUILD OGG OPUS CONTAINER
# =========================================================

OGG_FILE = "remote_opus.ogg"
WAV_FILE  = "remote.wav"

SAMPLE_RATE   = 48000
CHANNEL_COUNT = 1
SERIAL        = 0x12345678

# ----------------------------------------------------------
# Ogg CRC32 — polynomial 0x04c11db7, no pre/post inversion
# (different from standard CRC32 / zlib)
# ----------------------------------------------------------

_OGG_CRC_TABLE = []
for _i in range(256):
    _r = _i << 24
    for _ in range(8):
        _r = ((_r << 1) ^ 0x04c11db7) if (_r & 0x80000000) else (_r << 1)
        _r &= 0xFFFFFFFF
    _OGG_CRC_TABLE.append(_r)

def ogg_crc32(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = ((crc << 8) ^ _OGG_CRC_TABLE[((crc >> 24) ^ b) & 0xFF]) & 0xFFFFFFFF
    return crc

# ----------------------------------------------------------
# Build one Ogg page from a single packet (no multi-segment)
#
# Ogg page layout (RFC 3533):
#   4B  capture_pattern  "OggS"
#   1B  version          0
#   1B  header_type      flags
#   8B  granule_pos      int64 LE
#   4B  serial           uint32 LE
#   4B  page_seq         uint32 LE
#   4B  checksum         uint32 LE  (zeroed before CRC pass)
#   1B  page_segments    number of entries in lacing table
#   nB  segment_table    lacing values
#   data
# ----------------------------------------------------------

def make_ogg_page(serial: int, page_seq: int, granule_pos: int,
                  payload: bytes, first: bool = False, last: bool = False) -> bytes:

    header_type = 0
    if first:
        header_type |= 0x02
    if last:
        header_type |= 0x04

    # Build lacing table: split payload into 255-byte segments
    # A packet is terminated by a segment < 255 bytes.
    # If the packet length is a multiple of 255 we append a 0-length segment.
    lacing = []
    remaining = len(payload)
    while remaining >= 255:
        lacing.append(255)
        remaining -= 255
    lacing.append(remaining)   # terminal segment (may be 0)

    seg_count  = len(lacing)
    seg_table  = bytes(lacing)

    # Fixed header (checksum field zeroed)
    header = struct.pack(
        "<4sBBqIIIB",   # note: all little-endian
        b"OggS",        # capture pattern
        0,              # stream structure version
        header_type,    # header type flags
        granule_pos,    # granule position (signed 64-bit)
        serial,         # bitstream serial number
        page_seq,       # page sequence number
        0,              # checksum — MUST be zero for CRC input
        seg_count,      # number of page segments
    )
    # struct "<4sBBqIIIB" = 4+1+1+8+4+4+4+1 = 27 bytes  ✓

    page = header + seg_table + payload

    # Compute CRC over the whole page (checksum field already zero)
    crc = ogg_crc32(page)

    # Patch checksum in at byte offset 22
    page = page[:22] + struct.pack("<I", crc) + page[26:]

    return page

# ----------------------------------------------------------
# OpusHead ID header  (RFC 7845 §5.1)
#
# Byte layout:
#   8B  magic      "OpusHead"
#   1B  version    1
#   1B  channels
#   2B  pre_skip   uint16 LE
#   4B  rate       uint32 LE   (original input sample rate)
#   2B  gain       int16  LE
#   1B  map_family 0 = RTP mono/stereo
# Total: 19 bytes
# ----------------------------------------------------------

def make_opus_id_header(channels: int, sample_rate: int, pre_skip: int = 312) -> bytes:
    return (
        b"OpusHead"
        + struct.pack("<B", 1)             # version
        + struct.pack("<B", channels)      # channel count
        + struct.pack("<H", pre_skip)      # pre-skip
        + struct.pack("<I", sample_rate)   # input sample rate
        + struct.pack("<h", 0)             # output gain
        + struct.pack("<B", 0)             # channel mapping family
    )  # = 8 + 1+1+2+4+2+1 = 19 bytes  ✓

# ----------------------------------------------------------
# OpusTags comment header  (RFC 7845 §5.2)
# ----------------------------------------------------------

def make_opus_comment_header() -> bytes:
    vendor = b"python-rtp-extractor"
    return (
        b"OpusTags"
        + struct.pack("<I", len(vendor))
        + vendor
        + struct.pack("<I", 0)   # zero user comments
    )

# ----------------------------------------------------------
# Write the Ogg file
# ----------------------------------------------------------

print(f"\nBuilding Ogg Opus container -> {OGG_FILE}")

FRAME_SAMPLES = 960   # 20 ms @ 48 kHz (standard VoIP Opus frame)

with open(OGG_FILE, "wb") as f:

    # Page 0 — ID header, granule_pos must be 0
    f.write(make_ogg_page(SERIAL, 0, 0, make_opus_id_header(CHANNEL_COUNT, SAMPLE_RATE), first=True))

    # Page 1 — comment header, granule_pos must be 0
    f.write(make_ogg_page(SERIAL, 1, 0, make_opus_comment_header()))

    # Audio pages
    granule_pos = 0
    for i, (seq, ts, frame) in enumerate(packets):
        granule_pos += FRAME_SAMPLES
        is_last = (i == len(packets) - 1)
        f.write(make_ogg_page(SERIAL, i + 2, granule_pos, frame, last=is_last))

print(f"Ogg Opus file written: {OGG_FILE}")

# =========================================================
# STEP 8 - DECODE OGG OPUS TO WAV
# =========================================================

print("\nDecoding Ogg Opus to WAV...")

wav_result = subprocess.run(
    [
        "ffmpeg",
        "-i", OGG_FILE,
        "-ar", "48000",
        "-ac", str(CHANNEL_COUNT),
        "-c:a", "pcm_s16le",
        WAV_FILE,
        "-y"
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

if wav_result.returncode != 0:
    print("FFmpeg decode failed. stderr:")
    print(wav_result.stderr.decode())
else:
    size_kb = os.path.getsize(WAV_FILE) / 1024
    print(f"WAV audio saved: {WAV_FILE} ({size_kb:.1f} KB)")

print("\nDONE.")
print("Remote person's Opus voice extracted successfully.")

import requests

# Your ngrok public URL
url = "https://slip-viable-empathy.ngrok-free.dev/predict"

# Audio file path
audio_path = "remote.wav"

try:

    with open(audio_path, "rb") as audio_file:

        files = {
            "file": audio_file
        }

        print("\nSending audio for prediction...")

        response = requests.post(url, files=files)

    print("\nResponse Status:")
    print(response.status_code)

    print("\nPrediction Result:")
    print(response.json())

except Exception as e:

    print("Error:")
    print(e)
