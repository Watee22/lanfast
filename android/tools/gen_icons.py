"""生成 Android 图标（启动图标 + 通知栏小图标）以及 Windows 的 .ico。需要 Pillow。"""
import os
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RES = os.path.join(ROOT, "android", "res")

# 闪电形状（0~1 坐标）
BOLT = [(0.58, 0.10), (0.26, 0.56), (0.47, 0.56), (0.40, 0.90), (0.74, 0.42), (0.53, 0.42), (0.62, 0.10)]


def launcher(size):
    s = size * 4  # 超采样抗锯齿
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = int(s * 0.04)
    d.rounded_rectangle((pad, pad, s - pad, s - pad), radius=int(s * 0.22), fill=(37, 99, 235, 255))
    d.polygon([(x * s, y * s) for x, y in BOLT], fill=(255, 255, 255, 255))
    return img.resize((size, size), Image.LANCZOS)


def stat_icon(size):
    s = size * 4
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ImageDraw.Draw(img).polygon([(x * s, y * s) for x, y in BOLT], fill=(255, 255, 255, 255))
    return img.resize((size, size), Image.LANCZOS)


def main():
    for dpi, scale in (("mdpi", 1), ("hdpi", 1.5), ("xhdpi", 2), ("xxhdpi", 3), ("xxxhdpi", 4)):
        for folder, fn, base, maker in (("mipmap", "ic_launcher.png", 48, launcher),
                                        ("drawable", "ic_stat.png", 24, stat_icon)):
            out = os.path.join(RES, f"{folder}-{dpi}")
            os.makedirs(out, exist_ok=True)
            maker(int(base * scale)).save(os.path.join(out, fn))
    ico = os.path.join(ROOT, "windows", "lanfast.ico")
    launcher(256).save(ico, sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("icons generated")


if __name__ == "__main__":
    main()
