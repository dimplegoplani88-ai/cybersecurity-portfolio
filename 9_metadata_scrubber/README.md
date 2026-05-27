# 🧹 Project 9 — Metadata Scrubber

Remove EXIF and privacy metadata from images before sharing them online. Supports JPEG, PNG, TIFF, and WEBP formats.

## Why This Matters

Photos taken on phones and cameras embed hidden metadata including GPS coordinates, device model, timestamps, and author info. Sharing images without scrubbing this data can unintentionally expose your location and identity.

## Features

- Removes all EXIF metadata (GPS, camera model, timestamps, author info)
- Supports JPEG, PNG, TIFF, WEBP
- Batch process entire folders
- Dry-run mode to preview what would be removed
- Read-only mode to inspect metadata without modifying files
- Shows file size before and after

## Requirements

```bash
pip install Pillow piexif
```

## Usage

```bash
# Scrub a single image
python metadata_scrubber.py photo.jpg

# Scrub to a specific output folder
python metadata_scrubber.py photo.jpg -o clean/

# Scrub an entire folder of images
python metadata_scrubber.py ./photos/ -o ./clean/

# Preview only (no files modified)
python metadata_scrubber.py photo.jpg --dry-run

# Just view what metadata exists
python metadata_scrubber.py photo.jpg --read-only

# Verbose: show all metadata fields before scrubbing
python metadata_scrubber.py photo.jpg -v
```

## Skills Demonstrated

- EXIF metadata parsing with `piexif`
- Image processing with `Pillow`
- Privacy-focused tool design
- File I/O and batch processing
- Defensive security / data sanitisation
