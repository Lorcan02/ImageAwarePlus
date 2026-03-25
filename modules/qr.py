from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

import cv2
import numpy as np


@dataclass
class QRResult:
    found: bool
    data: Optional[str]
    # FIX 1: Tightened type annotation from `list | None` to
    # `List[List[List[int]]] | None` to accurately reflect what
    # cv2's points.tolist() actually produces — a nested list of
    # corner coordinates: [[[x1,y1], [x2,y2], [x3,y3], [x4,y4]]].
    # This makes it much clearer for callers and avoids ambiguity.
    points: Optional[List[List[List[int]]]]
    # FIX 2: Added extracted_url field. QR codes in phishing images almost
    # always encode a URL. Previously callers had to inspect `data` themselves
    # and re-implement URL extraction logic. Now extracted here at the source.
    extracted_url: Optional[str] = field(default=None)


def _extract_url_from_qr_data(data: str) -> Optional[str]:
    """
    FIX 2 (implementation): Extract a URL from decoded QR data.
    Handles the common cases:
      - data IS a URL (starts with http:// or https://)
      - data contains a URL alongside other text
      - data is a bare domain (www.example.com)
    """
    if not data:
        return None

    # Direct URL — most common case for phishing QR codes
    if re.match(r"^https?://", data.strip(), re.IGNORECASE):
        return data.strip()

    # URL embedded in mixed content
    match = re.search(r"https?://[^\s]+", data, re.IGNORECASE)
    if match:
        url = match.group(0).strip(").,;:'\"[]<>")
        return url

    # Bare www. domain
    match = re.search(r"www\.[^\s]{4,}", data, re.IGNORECASE)
    if match:
        return match.group(0).strip(").,;:'\"[]<>")

    return None


def _try_detect(img: np.ndarray) -> tuple[str, Optional[np.ndarray]]:
    """Run OpenCV QR detection on a single image variant."""
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)
    return data, points


def detect_and_decode_qr(img_bgr_or_gray: np.ndarray) -> QRResult:
    """
    Detect and decode a QR code using OpenCV.

    FIX 3: Multi-pass detection strategy. The original ran a single pass on
    whatever image was provided. OpenCV's QRCodeDetector is sensitive to:
      - Image contrast (low contrast → miss)
      - Colour channels (BGR vs grayscale)
      - Image sharpness (blur → miss)

    Now tries multiple variants in order:
      1. Original image as-is
      2. Grayscale conversion (if input was BGR)
      3. Sharpened grayscale (unsharp mask — helps with slightly blurry QR codes)
      4. Otsu-thresholded (high contrast binary — helps with faded/noisy images)

    Returns on the first successful decode.
    """
    variants = [img_bgr_or_gray]

    # Build grayscale variant if input looks like a BGR image
    if len(img_bgr_or_gray.shape) == 3 and img_bgr_or_gray.shape[2] == 3:
        gray = cv2.cvtColor(img_bgr_or_gray, cv2.COLOR_BGR2GRAY)
        variants.append(gray)

        # FIX 3 (cont): Sharpened variant — unsharp mask boosts edge contrast
        # which helps the QR finder pattern detector lock on to blurry codes.
        blurred = cv2.GaussianBlur(gray, (0, 0), 3)
        sharpened = cv2.addWeighted(gray, 1.5, blurred, -0.5, 0)
        variants.append(sharpened)

        # FIX 3 (cont): Otsu binary variant for faded or low-contrast QR codes
        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        variants.append(otsu)

    elif len(img_bgr_or_gray.shape) == 2:
        # Already grayscale — add sharpened and otsu variants
        gray = img_bgr_or_gray
        blurred = cv2.GaussianBlur(gray, (0, 0), 3)
        sharpened = cv2.addWeighted(gray, 1.5, blurred, -0.5, 0)
        variants.append(sharpened)

        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        variants.append(otsu)

    for variant in variants:
        data, points = _try_detect(variant)
        if data and points is not None:
            extracted_url = _extract_url_from_qr_data(data)
            return QRResult(
                found=True,
                data=data,
                points=points.tolist(),
                extracted_url=extracted_url,
            )

    return QRResult(found=False, data=None, points=None, extracted_url=None)


def draw_qr_bbox(img_bgr: np.ndarray, points: Optional[List]) -> np.ndarray:
    """
    Draw a bounding polygon around QR code corner points on an image.

    FIX 4: Added points validation before reshape. The original called
    np.array(points).reshape((-1, 1, 2)) unconditionally. If points was an
    unexpected shape (e.g. a partially-decoded result or a single point), the
    reshape would raise a cryptic ValueError from inside numpy/cv2 rather than
    a clear error message. Now validates first and returns the original image
    unchanged rather than crashing if points are invalid.
    """
    if points is None:
        return img_bgr

    try:
        pts_array = np.array(points, dtype=np.int32)

        # Must be reshapeable to (N, 1, 2) — i.e. have an even total element count
        # and at least 3 points to form a polygon.
        total_coords = pts_array.size
        if total_coords < 6 or total_coords % 2 != 0:
            return img_bgr

        pts = pts_array.reshape((-1, 1, 2))
        annotated = img_bgr.copy()
        cv2.polylines(
            annotated,
            [pts],
            isClosed=True,
            color=(0, 255, 0),
            thickness=3,
        )
        return annotated

    except (ValueError, cv2.error):
        # If anything goes wrong with the points, return the image unchanged
        # rather than crashing the whole analysis pipeline.
        return img_bgr