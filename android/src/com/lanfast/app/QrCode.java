package com.lanfast.app;

import android.graphics.Bitmap;
import android.graphics.Color;

import java.nio.charset.Charset;
import java.util.Arrays;

/**
 * 极简标准 QR Code 编码器（ISO/IEC 18004，Byte 模式，纠错等级 M，支持 Version 1~10）
 * 纯 Java 零第三方依赖，直接渲染为 Android Bitmap（自带 4 格纯白静区，iPhone/安卓相机即扫即识）。
 */
public class QrCode {
    static final Charset UTF8 = Charset.forName("UTF-8");

    // {ecPerBlock, g1Blocks, g1Data, g2Blocks, g2Data}
    static final int[][] VER_SPEC = {
            null,
            {10, 1, 16, 0, 0},
            {16, 1, 28, 0, 0},
            {26, 1, 44, 0, 0},
            {18, 2, 32, 0, 0},
            {24, 2, 43, 0, 0},
            {16, 4, 27, 0, 0},
            {18, 4, 31, 0, 0},
            {22, 2, 38, 2, 39},
            {22, 3, 36, 2, 37},
            {26, 4, 43, 1, 44},
    };
    static final int[][] ALIGN = {
            null, {}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34},
            {6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50},
    };

    static final int[] EXP = new int[512];
    static final int[] LOG = new int[256];

    static {
        int v = 1;
        for (int i = 0; i < 255; i++) {
            EXP[i] = v;
            LOG[v] = i;
            v <<= 1;
            if ((v & 0x100) != 0) v ^= 0x11D;
        }
        for (int i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
    }

    static int gfMul(int a, int b) {
        return (a == 0 || b == 0) ? 0 : EXP[LOG[a] + LOG[b]];
    }

    static int[] rsRem(int[] data, int deg) {
        int[] gen = new int[]{1};
        for (int i = 0; i < deg; i++) {
            int[] nxt = new int[gen.length + 1];
            int root = EXP[i];
            for (int j = 0; j < gen.length; j++) {
                nxt[j] ^= gen[j];
                nxt[j + 1] ^= gfMul(gen[j], root);
            }
            gen = nxt;
        }
        int[] rem = new int[deg];
        for (int b : data) {
            int factor = b ^ rem[0];
            System.arraycopy(rem, 1, rem, 0, deg - 1);
            rem[deg - 1] = 0;
            if (factor != 0) {
                for (int i = 0; i < deg; i++) rem[i] ^= gfMul(gen[i + 1], factor);
            }
        }
        return rem;
    }

    static int formatBits(int mask) {
        int data = mask; // EC level M = 00
        int rem = data;
        for (int i = 0; i < 10; i++) rem = (rem << 1) ^ (((rem >> 9) & 1) * 0x537);
        return ((data << 10) | rem) ^ 0x5412;
    }

    static int versionBits(int ver) {
        int rem = ver;
        for (int i = 0; i < 12; i++) rem = (rem << 1) ^ (((rem >> 11) & 1) * 0x1F25);
        return (ver << 12) | rem;
    }

    static boolean maskCond(int m, int r, int c) {
        switch (m) {
            case 0: return ((r + c) & 1) == 0;
            case 1: return (r & 1) == 0;
            case 2: return c % 3 == 0;
            case 3: return (r + c) % 3 == 0;
            case 4: return (((r / 2) + (c / 3)) & 1) == 0;
            case 5: return ((r * c) & 1) + ((r * c) % 3) == 0;
            case 6: return ((((r * c) & 1) + ((r * c) % 3)) & 1) == 0;
            default: return ((((r + c) & 1) + ((r * c) % 3)) & 1) == 0;
        }
    }

    static int penalty(boolean[][] g) {
        int n = g.length, score = 0, dark = 0;
        for (int r = 0; r < n; r++) {
            int run = 1;
            boolean prev = g[r][0];
            if (prev) dark++;
            for (int c = 1; c < n; c++) {
                boolean v = g[r][c];
                if (v) dark++;
                if (v == prev) {
                    run++;
                    if (run == 5) score += 3;
                    else if (run > 5) score++;
                } else {
                    run = 1;
                    prev = v;
                }
            }
        }
        for (int c = 0; c < n; c++) {
            int run = 1;
            boolean prev = g[0][c];
            for (int r = 1; r < n; r++) {
                if (g[r][c] == prev) {
                    run++;
                    if (run == 5) score += 3;
                    else if (run > 5) score++;
                } else {
                    run = 1;
                    prev = g[r][c];
                }
            }
        }
        for (int r = 0; r < n - 1; r++) {
            for (int c = 0; c < n - 1; c++) {
                boolean v = g[r][c];
                if (v == g[r][c + 1] && v == g[r + 1][c] && v == g[r + 1][c + 1]) score += 3;
            }
        }
        score += Math.abs((dark * 20) / (n * n) - 10) * 10;
        return score;
    }

    public static boolean[][] encode(String text) {
        byte[] payload = text.getBytes(UTF8);
        int ver = -1;
        for (int v = 1; v <= 10; v++) {
            int[] sp = VER_SPEC[v];
            int cap = sp[1] * sp[2] + sp[3] * sp[4];
            int hdr = v <= 9 ? 2 : 3;
            if (payload.length + hdr <= cap) {
                ver = v;
                break;
            }
        }
        if (ver < 0) throw new IllegalArgumentException("二维码内容过长（最多 210 字节）");

        int[] sp = VER_SPEC[ver];
        int ecLen = sp[0], g1 = sp[1], d1 = sp[2], g2 = sp[3], d2 = sp[4];
        int dataCap = g1 * d1 + g2 * d2;

        // 1) Byte mode bitstream
        int[] bits = new int[dataCap * 8];
        int bi = 0;
        bi = pushBits(bits, bi, 0x4, 4);
        bi = pushBits(bits, bi, payload.length, ver <= 9 ? 8 : 16);
        for (byte b : payload) bi = pushBits(bits, bi, b & 0xff, 8);
        int term = Math.min(4, bits.length - bi);
        bi += term;
        while ((bi & 7) != 0) bi++;

        int[] dataBytes = new int[dataCap];
        int nBytes = bi / 8;
        for (int i = 0; i < nBytes; i++) {
            int val = 0;
            for (int j = 0; j < 8; j++) val = (val << 1) | bits[i * 8 + j];
            dataBytes[i] = val;
        }
        for (int i = nBytes, p = 0; i < dataCap; i++, p ^= 1) {
            dataBytes[i] = p == 0 ? 0xEC : 0x11;
        }

        // 2) Reed-Solomon blocks + interleave
        int totalBlocks = g1 + g2;
        int[][] blocks = new int[totalBlocks][];
        int[][] ecs = new int[totalBlocks][];
        int off = 0, bIdx = 0;
        for (int i = 0; i < g1; i++) {
            blocks[bIdx] = Arrays.copyOfRange(dataBytes, off, off + d1);
            ecs[bIdx] = rsRem(blocks[bIdx], ecLen);
            off += d1;
            bIdx++;
        }
        for (int i = 0; i < g2; i++) {
            blocks[bIdx] = Arrays.copyOfRange(dataBytes, off, off + d2);
            ecs[bIdx] = rsRem(blocks[bIdx], ecLen);
            off += d2;
            bIdx++;
        }

        int[] codewords = new int[dataCap + totalBlocks * ecLen];
        int ci = 0, maxD = Math.max(d1, d2);
        for (int i = 0; i < maxD; i++) {
            for (int b = 0; b < totalBlocks; b++) {
                if (i < blocks[b].length) codewords[ci++] = blocks[b][i];
            }
        }
        for (int i = 0; i < ecLen; i++) {
            for (int b = 0; b < totalBlocks; b++) codewords[ci++] = ecs[b][i];
        }

        // 3) Function patterns
        int size = ver * 4 + 17;
        boolean[][] grid = new boolean[size][size];
        boolean[][] func = new boolean[size][size];

        placeFinder(grid, func, 0, 0);
        placeFinder(grid, func, 0, size - 7);
        placeFinder(grid, func, size - 7, 0);

        for (int i = 8; i < size - 8; i++) {
            setFn(grid, func, 6, i, (i & 1) == 0);
            setFn(grid, func, i, 6, (i & 1) == 0);
        }
        int[] al = ALIGN[ver];
        for (int r0 : al) {
            for (int c0 : al) {
                if ((r0 == 6 && c0 == 6) || (r0 == 6 && c0 == size - 7) || (r0 == size - 7 && c0 == 6)) continue;
                for (int dr = -2; dr <= 2; dr++) {
                    for (int dc = -2; dc <= 2; dc++) {
                        setFn(grid, func, r0 + dr, c0 + dc, Math.max(Math.abs(dr), Math.abs(dc)) != 1);
                    }
                }
            }
        }
        setFn(grid, func, size - 8, 8, true);
        for (int i = 0; i < 9; i++) {
            if (i != 6) {
                setFn(grid, func, 8, i, false);
                setFn(grid, func, i, 8, false);
            }
        }
        for (int i = 0; i < 8; i++) {
            setFn(grid, func, 8, size - 1 - i, false);
            setFn(grid, func, size - 1 - i, 8, false);
        }
        if (ver >= 7) {
            int vb = versionBits(ver);
            for (int i = 0; i < 18; i++) {
                boolean bit = ((vb >> i) & 1) != 0;
                int a = size - 11 + (i % 3), b = i / 3;
                setFn(grid, func, a, b, bit);
                setFn(grid, func, b, a, bit);
            }
        }

        // 4) Place data bits
        int cwBitTotal = codewords.length * 8;
        int bitPos = 0;
        boolean up = true;
        int col = size - 1;
        while (col > 0) {
            if (col == 6) col--;
            for (int step = 0; step < size; step++) {
                int r = up ? (size - 1 - step) : step;
                for (int dc = 0; dc >= -1; dc--) {
                    int cc = col + dc;
                    if (!func[r][cc]) {
                        boolean v = false;
                        if (bitPos < cwBitTotal) {
                            v = ((codewords[bitPos >> 3] >> (7 - (bitPos & 7))) & 1) != 0;
                        }
                        grid[r][cc] = v;
                        bitPos++;
                    }
                }
            }
            col -= 2;
            up = !up;
        }

        // 5) Best mask
        boolean[][] best = null;
        int bestScore = Integer.MAX_VALUE;
        for (int m = 0; m < 8; m++) {
            boolean[][] cand = new boolean[size][size];
            for (int r = 0; r < size; r++) {
                for (int c = 0; c < size; c++) {
                    cand[r][c] = (!func[r][c] && maskCond(m, r, c)) ? !grid[r][c] : grid[r][c];
                }
            }
            int fb = formatBits(m);
            for (int i = 0; i < 6; i++) cand[8][i] = ((fb >> (14 - i)) & 1) != 0;
            cand[8][7] = ((fb >> 8) & 1) != 0;
            cand[8][8] = ((fb >> 7) & 1) != 0;
            cand[7][8] = ((fb >> 6) & 1) != 0;
            for (int i = 0; i < 6; i++) cand[5 - i][8] = ((fb >> (5 - i)) & 1) != 0;
            for (int i = 0; i < 8; i++) cand[8][size - 1 - i] = ((fb >> i) & 1) != 0;
            for (int i = 0; i < 7; i++) cand[size - 1 - i][8] = ((fb >> (14 - i)) & 1) != 0;

            int sc = penalty(cand);
            if (sc < bestScore) {
                bestScore = sc;
                best = cand;
            }
        }
        return best;
    }

    static int pushBits(int[] bits, int pos, int val, int len) {
        for (int i = len - 1; i >= 0; i--) bits[pos++] = (val >> i) & 1;
        return pos;
    }

    static void setFn(boolean[][] g, boolean[][] f, int r, int c, boolean v) {
        if (r >= 0 && r < g.length && c >= 0 && c < g.length) {
            g[r][c] = v;
            f[r][c] = true;
        }
    }

    static void placeFinder(boolean[][] g, boolean[][] f, int r0, int c0) {
        for (int dr = -1; dr <= 7; dr++) {
            for (int dc = -1; dc <= 7; dc++) {
                boolean dark = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6
                        && (dr == 0 || dr == 6 || dc == 0 || dc == 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
                setFn(g, f, r0 + dr, c0 + dc, dark);
            }
        }
    }

    public static Bitmap toBitmap(String text, int targetPx) {
        boolean[][] m = encode(text);
        int n = m.length, quiet = 4, total = n + quiet * 2;
        int cell = Math.max(4, targetPx / total);
        int imgSize = total * cell;
        int[] px = new int[imgSize * imgSize];
        Arrays.fill(px, Color.WHITE);
        for (int r = 0; r < n; r++) {
            for (int c = 0; c < n; c++) {
                if (m[r][c]) {
                    int y0 = (r + quiet) * cell, x0 = (c + quiet) * cell;
                    for (int dy = 0; dy < cell; dy++) {
                        int rowOff = (y0 + dy) * imgSize + x0;
                        for (int dx = 0; dx < cell; dx++) px[rowOff + dx] = Color.BLACK;
                    }
                }
            }
        }
        Bitmap bmp = Bitmap.createBitmap(imgSize, imgSize, Bitmap.Config.ARGB_8888);
        bmp.setPixels(px, 0, imgSize, 0, 0, imgSize, imgSize);
        return bmp;
    }
}
