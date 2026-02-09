import random
import subprocess
import json
from pathlib import Path

# Get all sample files
email_dir = Path('phishing_pot/email')
all_samples = list(email_dir.glob('sample-*.eml'))
print(f"Total emails available: {len(all_samples)}")

# Random sample of 500
random.seed(42)  # For reproducibility
sample_files = random.sample(all_samples, min(500, len(all_samples)))
print(f"Sampling {len(sample_files)} emails...")

# Create temporary directory for samples
sample_dir = Path('large_sample_batch')
sample_dir.mkdir(exist_ok=True)

# Copy samples
print("Copying samples...")
for i, src in enumerate(sample_files, 1):
    if i % 50 == 0:
        print(f"  Copied {i}/500...")
    dest = sample_dir / src.name
    dest.write_bytes(src.read_bytes())

print(f"\nSamples ready in {sample_dir}/")
print("Run: python phishing_detector.py large_sample_batch/")
print("This will take 3-5 minutes...")
