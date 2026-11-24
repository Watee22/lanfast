import ctypes
import sys

if sys.platform.startswith("win"):
    try:  # 高 DPI 屏幕下界面不模糊
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa
        pass

from lanfast.gui import main

if __name__ == "__main__":
    main()
