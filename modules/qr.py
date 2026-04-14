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
    
    points: Optional[List[List[List[int]]]]
    
    extracted_url: Optional[str] = field(default=None)


def _extract_url_from_qr_data(data: str) -> Optional[str]:
   
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
    
    variants = [img_bgr_or_gray]

    # Build grayscale variant if input looks like a BGR image
    if len(img_bgr_or_gray.shape) == 3 and img_bgr_or_gray.shape[2] == 3:
        gray = cv2.cvtColor(img_bgr_or_gray, cv2.COLOR_BGR2GRAY)
        variants.append(gray)

        
        blurred = cv2.GaussianBlur(gray, (0, 0), 3)
        sharpened = cv2.addWeighted(gray, 1.5, blurred, -0.5, 0)
        variants.append(sharpened)

        
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