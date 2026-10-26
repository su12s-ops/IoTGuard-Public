"""Generate small synthetic camera frames; Pillow is needed only on the build host."""
from pathlib import Path
from PIL import Image, ImageDraw


def build(root=None):
    root = Path(root) if root else Path(__file__).parent / "frames"
    palette = [(235,235,235), (235,235,16), (16,235,235), (16,235,16),
               (235,16,235), (235,16,16), (16,16,235), (20,20,20)]
    for camera in ("cam01", "cam02"):
        target = root / camera
        target.mkdir(parents=True, exist_ok=True)
        for frame in range(12):
            image = Image.new("RGB", (640, 360), "#122038")
            draw = ImageDraw.Draw(image)
            colors = palette if camera == "cam01" else list(reversed(palette))
            for i, color in enumerate(colors):
                draw.rectangle((i*80, 70, (i+1)*80, 300), fill=color)
            draw.rectangle((0, 0, 640, 64), fill="#122038")
            draw.text((20, 20), f"IoTGuard {camera.upper()} | SIMULATED CAMERA", fill="white")
            x = 20 + frame * 48
            draw.rectangle((x, 160, x+38, 210), outline="white", width=4)
            draw.text((20, 325), f"Synthetic test pattern | frame {frame+1:02}/12 | 2 fps", fill="white")
            image.save(target / f"frame-{frame:02}.jpg", quality=72, optimize=True)


if __name__ == "__main__":
    build()
