# Metadata Scrubber Tool

A Python CLI tool that **reads and removes EXIF metadata** from images to protect your privacy before sharing photos online.

## Why This Matters

Every photo taken with a smartphone or digital camera embeds hidden metadata including:

- **GPS coordinates** — exact location where the photo was taken
- **Device information** — make, model, and serial number of your camera/phone
- **Timestamps** — when the photo was created and modified
- **Author/copyright** — name and personal info embedded by some apps

When you upload a photo to social media, blogs, or messaging apps, this data often travels with it — exposing where you live, work, or were at a given time.

## Features

- Strip all EXIF metadata from JPEG, PNG, TIFF, and WEBP images
- Batch-process entire directories
- Preview metadata before removing (`--read-only`)
- Dry-run mode to see what would be removed without modifying files
- Verbose mode to inspect full metadata fields
- Saves output to a separate folder — originals are never overwritten

## Requirements

- Python 3.6+
- Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### View metadata only

```bash
python metadata_scrubber.py photo.jpg --read-only
```

### Scrub a single image

```bash
python metadata_scrubber.py photo.jpg
# Output saved to ./scrubbed/photo.jpg
```

### Scrub to a custom output directory

```bash
python metadata_scrubber.py photo.jpg -o ./clean_photos/
```

### Batch scrub an entire folder

```bash
python metadata_scrubber.py ./my_photos/ -o ./clean_photos/
```

### Dry run (preview without saving)

```bash
python metadata_scrubber.py photo.jpg --dry-run
```

### Verbose output (show all fields being removed)

```bash
python metadata_scrubber.py photo.jpg -v
```

## Supported Formats

| Format | Extension |
|--------|-----------|
| JPEG   | `.jpg`, `.jpeg` |
| PNG    | `.png` |
| TIFF   | `.tiff`, `.tif` |
| WebP   | `.webp` |

## What You'll Learn

- How EXIF metadata is structured (IFD tags, GPS IFD, TIFF headers)
- Privacy implications of image metadata
- How to use Python's `Pillow` for image processing
- Batch file processing with `pathlib`
- Building CLI tools with `argparse`

## Disclaimer

This tool is for legitimate privacy protection purposes. Always ensure you have permission to modify any files you do not own.
