package webui

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func readBrandPNG(t *testing.T, parts ...string) (image.Image, []byte) {
	t.Helper()
	path := filepath.Join(parts...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	decoded, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return decoded, data
}

func alphaAt(value image.Image, x, y int) uint32 {
	_, _, _, alpha := value.At(x, y).RGBA()
	return alpha
}

func nrgbaAt(value image.Image, x, y int) color.NRGBA {
	return color.NRGBAModel.Convert(value.At(x, y)).(color.NRGBA)
}

func visibleWidth(value image.Image) int {
	bounds := value.Bounds()
	left, right := bounds.Max.X, bounds.Min.X
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if alphaAt(value, x, y) < 0x8000 {
				continue
			}
			if x < left {
				left = x
			}
			if x > right {
				right = x
			}
		}
	}
	if right < left {
		return 0
	}
	return right - left + 1
}

func readWindowsIcon(t *testing.T, path string) []image.Image {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(data) < 6 || binary.LittleEndian.Uint16(data[0:2]) != 0 || binary.LittleEndian.Uint16(data[2:4]) != 1 {
		t.Fatalf("%s is not a Windows icon directory", path)
	}
	count := int(binary.LittleEndian.Uint16(data[4:6]))
	if len(data) < 6+count*16 {
		t.Fatalf("%s has a truncated icon directory", path)
	}
	images := make([]image.Image, 0, count)
	for index := 0; index < count; index++ {
		entry := 6 + index*16
		size := int(data[entry])
		if size == 0 {
			size = 256
		}
		length := int(binary.LittleEndian.Uint32(data[entry+8 : entry+12]))
		offset := int(binary.LittleEndian.Uint32(data[entry+12 : entry+16]))
		if length <= 0 || offset < 0 || offset+length > len(data) {
			t.Fatalf("%s entry %d points outside the file", path, index)
		}
		decoded, err := png.Decode(bytes.NewReader(data[offset : offset+length]))
		if err != nil {
			t.Fatalf("decode %s entry %d: %v", path, index, err)
		}
		if decoded.Bounds().Dx() != size || decoded.Bounds().Dy() != size {
			t.Fatalf("%s entry %d dimensions = %v, want %dx%d", path, index, decoded.Bounds(), size, size)
		}
		images = append(images, decoded)
	}
	return images
}

func TestBrandAssetsPreservePurposeSpecificTransparency(t *testing.T) {
	standard, _ := readBrandPNG(t, "..", "..", "web", "public", "haven-app-icon-512.png")
	maskable, _ := readBrandPNG(t, "..", "..", "web", "public", "haven-maskable-icon-512.png")
	desktop, _ := readBrandPNG(t, "..", "..", "desktop", "build", "icon.png")

	for label, value := range map[string]image.Image{"standard": standard, "desktop": desktop} {
		if got := alphaAt(value, 0, 0); got != 0 {
			t.Fatalf("%s icon corner alpha = %d, want transparent", label, got)
		}
		bounds := value.Bounds()
		if got := alphaAt(value, bounds.Dx()/2, bounds.Dy()/2); got != 0xffff {
			t.Fatalf("%s icon center alpha = %d, want opaque mark", label, got)
		}
	}

	for _, coordinate := range [][2]int{{0, 0}, {511, 0}, {0, 511}, {511, 511}} {
		if got := alphaAt(maskable, coordinate[0], coordinate[1]); got != 0xffff {
			t.Fatalf("maskable icon corner %v alpha = %d, want opaque", coordinate, got)
		}
	}
	if visibleWidth(desktop)*100 < visibleWidth(standard)*112 {
		t.Fatalf("desktop mark width = %d, standard mark width = %d; want Windows mark optically larger", visibleWidth(desktop), visibleWidth(standard))
	}

	windowsIcons := readWindowsIcon(t, filepath.Join("..", "..", "desktop", "build", "icon.ico"))
	expectedSizes := []int{16, 20, 24, 32, 40, 48, 64, 128, 256}
	if len(windowsIcons) != len(expectedSizes) {
		t.Fatalf("Windows icon entries = %d, want %d", len(windowsIcons), len(expectedSizes))
	}
	for index, value := range windowsIcons {
		size := expectedSizes[index]
		if value.Bounds().Dx() != size {
			t.Fatalf("Windows icon entry %d = %dpx, want %dpx", index, value.Bounds().Dx(), size)
		}
		if alphaAt(value, 0, 0) != 0 || alphaAt(value, size/2, size/2) != 0xffff {
			t.Fatalf("Windows icon entry %d does not preserve a transparent canvas and opaque mark", index)
		}
		if visibleWidth(value)*100 < size*70 {
			t.Fatalf("Windows icon entry %d occupies only %d of %d pixels", index, visibleWidth(value), size)
		}
		upright := nrgbaAt(value, size*37/100, size/2)
		if upright.A < 0xf0 || upright.G < 0xa0 || upright.B < 0x80 || upright.G <= upright.R || upright.B <= upright.R {
			t.Fatalf("Windows icon entry %d lost its green-cyan monogram upright: %#v", index, upright)
		}
	}
}

func TestCanonicalBrandMarkRetainsApprovedShieldAndMonogramPalette(t *testing.T) {
	standard, _ := readBrandPNG(t, "..", "..", "web", "public", "haven-app-icon-512.png")
	want := map[string]struct {
		x, y  int
		color color.NRGBA
	}{
		"gradient rim":      {256, 45, color.NRGBA{R: 4, G: 211, B: 158, A: 255}},
		"cool inner line":   {256, 64, color.NRGBA{R: 224, G: 255, B: 248, A: 255}},
		"deep shield field": {256, 80, color.NRGBA{R: 7, G: 25, B: 36, A: 255}},
		"upper upright":     {180, 180, color.NRGBA{R: 70, G: 229, B: 177, A: 255}},
		"monogram bridge":   {256, 240, color.NRGBA{R: 55, G: 223, B: 190, A: 255}},
		"lower upright":     {320, 350, color.NRGBA{R: 25, G: 211, B: 215, A: 255}},
	}
	for label, sample := range want {
		if got := nrgbaAt(standard, sample.x, sample.y); got != sample.color {
			t.Fatalf("%s sample = %#v, want %#v", label, got, sample.color)
		}
	}
}
