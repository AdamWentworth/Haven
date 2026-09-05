package webui

import (
	"bytes"
	"image"
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

func TestBrandAssetsPreservePurposeSpecificTransparency(t *testing.T) {
	standard, standardBytes := readBrandPNG(t, "..", "..", "web", "public", "haven-app-icon-512.png")
	maskable, _ := readBrandPNG(t, "..", "..", "web", "public", "haven-maskable-icon-512.png")
	desktop, desktopBytes := readBrandPNG(t, "..", "..", "desktop", "build", "icon.png")

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
	if !bytes.Equal(standardBytes, desktopBytes) {
		t.Fatal("desktop and standard 512px brand marks drifted")
	}
}
