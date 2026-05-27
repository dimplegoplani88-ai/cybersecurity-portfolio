#!/usr/bin/env python3
"""
Metadata Scrubber Tool
Remove EXIF and privacy metadata from images.
Supports: JPEG, PNG, TIFF, WEBP
"""

import argparse
import os
import sys
from pathlib import Path

try:
    from PIL import Image
    import piexif
except ImportError:
    print("[!] Missing dependencies. Run: pip install Pillow piexif")
    sys.exit(1)


SUPPORTED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.tiff', '.tif', '.webp'}

SENSITIVE_EXIF_TAGS = {
    "GPS": ["GPSLatitude", "GPSLongitude", "GPSAltitude", "GPSTimeStamp",
            "GPSDateStamp", "GPSLatitudeRef", "GPSLongitudeRef"],
    "Camera": ["Make", "Model", "Software", "LensModel", "LensMake"],
    "Timestamps": ["DateTime", "DateTimeOriginal", "DateTimeDigitized"],
    "Author": ["Artist", "Copyright", "XPAuthor", "XPComment"],
}


def read_metadata(filepath: Path) -> dict:
    """Extract and display EXIF metadata from an image."""
    metadata = {}
    try:
        img = Image.open(filepath)
        exif_data = img.info.get("exif")

        if not exif_data:
            return {}

        exif_dict = piexif.load(exif_data)

        for ifd_name in exif_dict:
            if ifd_name == "thumbnail":
                continue
            ifd = exif_dict[ifd_name]
            for tag_id, value in ifd.items():
                tag_name = piexif.TAGS[ifd_name].get(tag_id, {}).get("name", str(tag_id))
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='replace').strip('\x00')
                    except Exception:
                        value = repr(value)
                metadata[f"{ifd_name}:{tag_name}"] = value

    except Exception as e:
        print(f"[!] Error reading metadata from {filepath.name}: {e}")

    return metadata


def scrub_metadata(input_path: Path, output_path: Path) -> bool:
    """Remove all EXIF metadata from an image and save to output path."""
    try:
        img = Image.open(input_path)

        # Convert mode if necessary for saving
        if img.mode in ("RGBA", "P") and output_path.suffix.lower() in ('.jpg', '.jpeg'):
            img = img.convert("RGB")

        # Save without any EXIF data
        img.save(output_path, exif=b"")
        return True

    except Exception as e:
        print(f"[!] Failed to scrub {input_path.name}: {e}")
        return False


def process_single(filepath: Path, output_dir: Path, dry_run: bool, verbose: bool) -> bool:
    """Process a single image file."""
    if filepath.suffix.lower() not in SUPPORTED_EXTENSIONS:
        print(f"[!] Skipping unsupported file: {filepath.name}")
        return False

    # Read metadata before
    metadata_before = read_metadata(filepath)

    if verbose:
        if metadata_before:
            print(f"\n[*] Metadata found in {filepath.name}:")
            for key, value in metadata_before.items():
                print(f"    {key}: {value}")
        else:
            print(f"[*] No EXIF metadata found in {filepath.name}")

    if dry_run:
        count = len(metadata_before)
        print(f"[DRY RUN] {filepath.name}: {count} metadata field(s) would be removed")
        return True

    # Determine output path
    output_path = output_dir / filepath.name

    success = scrub_metadata(filepath, output_path)

    if success:
        original_size = filepath.stat().st_size
        new_size = output_path.stat().st_size
        removed = len(metadata_before)
        print(f"[+] Scrubbed: {filepath.name}")
        print(f"    Fields removed: {removed}")
        print(f"    Size: {original_size:,} bytes → {new_size:,} bytes")
        print(f"    Saved to: {output_path}")
    return success


def main():
    parser = argparse.ArgumentParser(
        description="Metadata Scrubber — remove EXIF and privacy metadata from images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scrub single file:     python metadata_scrubber.py photo.jpg
  Scrub to output dir:   python metadata_scrubber.py photo.jpg -o clean/
  Scrub entire folder:   python metadata_scrubber.py ./photos/ -o ./clean/
  Preview only:          python metadata_scrubber.py photo.jpg --dry-run
  Show metadata:         python metadata_scrubber.py photo.jpg --read-only
        """
    )

    parser.add_argument("input", help="Image file or directory to process")
    parser.add_argument("-o", "--output", default="scrubbed",
                        help="Output directory (default: ./scrubbed)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview what would be removed without saving")
    parser.add_argument("--read-only", action="store_true",
                        help="Only display metadata, do not modify files")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed metadata before scrubbing")

    args = parser.parse_args()

    input_path = Path(args.input)

    if not input_path.exists():
        print(f"[!] Path not found: {input_path}")
        sys.exit(1)

    output_dir = Path(args.output)

    if not args.dry_run and not args.read_only:
        output_dir.mkdir(parents=True, exist_ok=True)

    # Collect files to process
    if input_path.is_dir():
        files = [f for f in input_path.iterdir()
                 if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS]
        if not files:
            print(f"[!] No supported image files found in {input_path}")
            sys.exit(0)
        print(f"[*] Found {len(files)} image(s) in {input_path}\n")
    else:
        files = [input_path]

    # Process
    success_count = 0
    for f in files:
        if args.read_only:
            metadata = read_metadata(f)
            print(f"\n[*] {f.name} — {len(metadata)} metadata field(s):")
            for key, value in metadata.items():
                print(f"    {key}: {value}")
            if not metadata:
                print("    (no EXIF data found)")
        else:
            if process_single(f, output_dir, args.dry_run, args.verbose):
                success_count += 1

    if not args.read_only:
        print(f"\n[*] Done. {success_count}/{len(files)} file(s) processed.")


if __name__ == "__main__":
    main()
