"""
Using Python To Extract Embedded Shellcode Or Payloads From Binaries

Security operations automation tool.
"""

def read_binary(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    return data
# Load the binary into memory
binary_data = read_binary("suspicious_sample.exe")
print(f"Binary loaded: {len(binary_data)} bytes")
# - Binary is read as raw bytes (`rb` mode).
# - Data is loaded into memory for in-memory inspection (important for shellcode
#   detection).
#
# A common technique is searching for NOP sleds (`\x90`) or syscall instructions
# (`\xCD\x80`, `\x0F\x05`).
def find_shellcode_patterns(data):
    matches = []
    # Simple heuristic: NOP sled + suspicious size
    pattern = b"\x90" * 10  # 10 or more NOPs in a row
    index = 0
    while True:
        index = data.find(pattern, index)
        if index == -1:
            break
        # Extract 300 bytes from that point (potential shellcode)
        snippet = data[index:index + 300]
        matches.append((index, snippet))
        index += 10  # Move forward to find next match
    return matches
results = find_shellcode_patterns(binary_data)
print(f"Found {len(results)} potential shellcode segments.")
# - Looks for a sequence of NOPs (often used as sleds before real shellcode).
# - Captures a 300-byte snippet starting from the match (can be adjusted).
# - This is a heuristic, not a guarantee — requires manual or automated disassembly
#   later.
#
# ## 4. Saving Extracted Payloads to Disk
import os
def save_payloads(matches, output_dir="extracted_payloads"):
    os.makedirs(output_dir, exist_ok=True)
    for i, (offset, payload) in enumerate(matches):
        filename = f"{output_dir}/payload_{i}_at_{offset}.bin"
        with open(filename, "wb") as f:
            f.write(payload)
        print(f"[+] Saved {filename} ({len(payload)} bytes)")
save_payloads(results)
# - Each shellcode segment found is written to a `.bin` file.
# - You can later load this into tools like `radare2`, `IDA`, or a custom emulator for
#   analysis.
#
# ## 5. Advanced Technique: Entropy Analysis
# Shellcode is typically high-entropy compared to regular code/data.
import math
def calculate_entropy(data):
    if not data:
        return 0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    entropy = 0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy
# Sliding window entropy analysis
window_size = 512
threshold = 7.5  # High-entropy threshold
high_entropy_regions = []
for i in range(0, len(binary_data) - window_size, 100):
    window = binary_data[i:i + window_size]
    entropy = calculate_entropy(window)
    if entropy > threshold:
        high_entropy_regions.append((i, entropy))
print(f"High-entropy regions found: {len(high_entropy_regions)}")
# - Slides a window through the binary.
# - Computes Shannon entropy (values close to 8.0 = high randomness).
# - Useful for identifying encrypted or packed sections.
#
# ## 6. Extracting Payloads Based on Entropy
# You can combine entropy with other heuristics:
def extract_high_entropy_regions(data, regions, window_size=512):
    payloads = []
    for offset, _ in regions:
        snippet = data[offset:offset + window_size]
        payloads.append((offset, snippet))
    return payloads
entropy_payloads = extract_high_entropy_regions(binary_data, high_entropy_regions)
save_payloads(entropy_payloads, output_dir="entropy_payloads")
# ## 7. Optional: Signature Matching (YARA Style)
# You can also use byte pattern matching (poor man's YARA):
import re
pattern = b"\xfc\xe8[\x00-\xff]{4}\x60\x89\xe5"
matches = list(re.finditer(pattern, binary_data))
print(f"Signature matches: {len(matches)}")