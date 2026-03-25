from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

import cv2
import numpy as np


@dataclass
class PreprocessConfig:
    """Configuration for preprocessing an image for OCR/QR detection."""
    max_width: int = 1200
    denoise: bool = True
    blur_kernel: Tuple[int, int] = (5, 5)
    threshold_method: str = "adaptive"  # "adaptive" or "otsu"

    # FIX 1: Added contrast enhancement option. Low-contrast phishing
    # screenshots (faded text, light-on-light) produce poor OCR results
    # without a contrast boost before thresholding. CLAHE (Contrast Limited
    # Adaptive Histogram Equalisation) handles this much better than a global
    # equalisation because it works on local regions — important for images
    # that have both dark and light areas (e.g. a branded header over a white
    # invoice body).
    enhance_contrast: bool = True
    clahe_clip_limit: float = 2.0
    clahe_tile_grid: Tuple[int, int] = (8, 8)

    # FIX 2: Added minimum size guard. Tiny images (thumbnails, icons, QR
    # fragments) produce garbage OCR. If the image is smaller than these
    # dimensions after loading, preprocessing will upscale it before OCR.
    min_width: int = 200
    min_height: int = 200


def load_image_bgr(image_path: str | Path) -> np.ndarray:
    """Load an image from disk in BGR format (OpenCV default)."""
    image_path = Path(image_path)
    if not image_path.exists():
        raise FileNotFoundError(f"Image not found: {image_path}")
    img = cv2.imread(str(image_path), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f"Failed to load image (unsupported/corrupt?): {image_path}")
    return img


def resize_keep_aspect(img: np.ndarray, max_width: int) -> np.ndarray:
    """Resize image to max_width while keeping aspect ratio (only if wider)."""
    h, w = img.shape[:2]
    if w <= max_width:
        return img
    scale = max_width / float(w)
    new_w = int(w * scale)
    new_h = int(h * scale)
    return cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_AREA)


def upscale_if_small(img: np.ndarray, min_width: int, min_height: int) -> np.ndarray:
    """
    FIX 2 (implementation): Upscale images that are too small for reliable
    OCR. Uses INTER_CUBIC which preserves text edge sharpness better than
    INTER_LINEAR when enlarging.
    """
    h, w = img.shape[:2]
    if w >= min_width and h >= min_height:
        return img
    scale = max(min_width / w, min_height / h)
    new_w = int(w * scale)
    new_h = int(h * scale)
    return cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_CUBIC)


def preprocess_for_ocr_and_qr(
    img_bgr: np.ndarray,
    cfg: Optional[PreprocessConfig] = None,
) -> dict:
    """
    Preprocesses an image and returns a dict of intermediate variants for
    use in multi-pass OCR and QR detection.

    Returns keys:
        original_bgr   — untouched input
        resized_bgr    — resized (and upscaled if small)
        gray           — grayscale
        denoised       — after blur
        thresh         — primary threshold (adaptive or otsu, per config)
        otsu           — always-present Otsu variant for multi-pass OCR
    """
    cfg = cfg or PreprocessConfig()

    # FIX 2 (applied): upscale before downscale so tiny images get enough
    # resolution for Tesseract, then cap at max_width as usual.
    upscaled = upscale_if_small(img_bgr, cfg.min_width, cfg.min_height)
    resized = resize_keep_aspect(upscaled, cfg.max_width)

    gray = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)

    # FIX 1 (applied): optional CLAHE contrast enhancement on the grayscale
    # image before denoising. Applied before blur so fine text edges are
    # sharpened first, then smoothed — not the other way around.
    if cfg.enhance_contrast:
        clahe = cv2.createCLAHE(
            clipLimit=cfg.clahe_clip_limit,
            tileGridSize=cfg.clahe_tile_grid,
        )
        gray = clahe.apply(gray)

    if cfg.denoise:
        denoised = cv2.GaussianBlur(gray, cfg.blur_kernel, 0)
    else:
        denoised = gray

    # FIX 3: Fixed misplaced comment. The original had a comment
    # `# --- Primary threshold ... ---` sitting INSIDE the `else: denoised = gray`
    # block due to incorrect indentation, making it look like dead code.
    # It is now correctly positioned before the threshold block.

    # --- Primary threshold (config-controlled) ---
    if cfg.threshold_method.lower() == "adaptive":
        thresh = cv2.adaptiveThreshold(
            denoised,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            31,  # block size (must be odd)
            7,   # constant subtracted from mean
        )
    elif cfg.threshold_method.lower() == "otsu":
        _, thresh = cv2.threshold(
            denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
        )
    else:
        raise ValueError("threshold_method must be 'adaptive' or 'otsu'")

    # --- Always produce an Otsu variant for multi-pass OCR ---
    _, otsu = cv2.threshold(
        denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
    )

    return {
        "original_bgr": img_bgr,
        "resized_bgr": resized,
        "gray": gray,
        "denoised": denoised,
        "thresh": thresh,
        "otsu": otsu,
    }


def save_debug_images(images: dict, out_dir: str | Path, stem: str = "sample") -> None:
    """Save intermediate preprocessing outputs to disk for debugging."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    mapping = {
        "resized_bgr": f"{stem}_1_resized.png",
        "gray":        f"{stem}_2_gray.png",
        "denoised":    f"{stem}_3_denoised.png",
        "thresh":      f"{stem}_4_thresh.png",
        # FIX 4: Added otsu to debug output — it was being generated but never
        # saved, making it impossible to visually inspect during development.
        "otsu":        f"{stem}_5_otsu.png",
    }

    for key, filename in mapping.items():
        if key in images and images[key] is not None:
            cv2.imwrite(str(out_dir / filename), images[key])