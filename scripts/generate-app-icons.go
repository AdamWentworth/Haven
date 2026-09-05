//go:build ignore

// Generate HAVEN's deterministic PWA raster icons from the same simple shield
// geometry as the bundled SVG. It uses only the Go standard library.
package main

import (
	"bytes"
	"flag"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

type point struct{ x, y float64 }

var shield = []point{
	{256, 64}, {416, 130}, {416, 246}, {409, 292}, {390, 337}, {357, 376},
	{312, 413}, {256, 436}, {200, 413}, {155, 376}, {122, 337}, {103, 292},
	{96, 246}, {96, 130},
}

func main() {
	check := flag.Bool("check", false, "verify committed icons match the deterministic generator")
	flag.Parse()
	assets := []struct {
		path  string
		size  int
		tiled bool
	}{
		{filepath.Join("web", "public", "haven-app-icon-192.png"), 192, false},
		{filepath.Join("web", "public", "haven-app-icon-512.png"), 512, false},
		{filepath.Join("web", "public", "haven-maskable-icon-512.png"), 512, true},
		{filepath.Join("desktop", "build", "icon.png"), 512, false},
	}
	for _, asset := range assets {
		generated := encode(render(asset.size, asset.tiled))
		if *check {
			committed, err := os.ReadFile(asset.path)
			if err != nil || !bytes.Equal(committed, generated) {
				panic("brand asset is missing or stale: " + asset.path)
			}
			continue
		}
		if err := os.WriteFile(asset.path, generated, 0o644); err != nil {
			panic(err)
		}
	}
}

func encode(value image.Image) []byte {
	var output bytes.Buffer
	if err := png.Encode(&output, value); err != nil {
		panic(err)
	}
	return output.Bytes()
}

func render(size int, tiled bool) *image.NRGBA {
	const samples = 4
	large := size * samples
	canvas := image.NewNRGBA(image.Rect(0, 0, size, size))
	background := color.RGBA{8, 16, 13, 255}
	shieldFill := color.RGBA{16, 37, 29, 255}
	green := color.RGBA{115, 226, 167, 255}
	pale := color.RGBA{223, 245, 232, 255}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var premultiplied [3]int
			alpha := 0
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					px := (float64(x*samples+sx) + .5) * 512 / float64(large)
					py := (float64(y*samples+sy) + .5) * 512 / float64(large)
					shade := color.RGBA{}
					if tiled {
						shade = background
					}
					if insidePolygon(point{px, py}, shield) {
						shade = shieldFill
					}
					if polygonDistance(point{px, py}, shield) <= 14 {
						shade = green
					}
					if lineDistance(point{px, py}, point{188, 170}, point{188, 342}) <= 14 ||
						lineDistance(point{px, py}, point{324, 170}, point{324, 342}) <= 14 ||
						lineDistance(point{px, py}, point{188, 256}, point{324, 256}) <= 14 {
						shade = pale
					}
					premultiplied[0] += int(shade.R) * int(shade.A)
					premultiplied[1] += int(shade.G) * int(shade.A)
					premultiplied[2] += int(shade.B) * int(shade.A)
					alpha += int(shade.A)
				}
			}
			count := samples * samples
			if alpha == 0 {
				canvas.SetNRGBA(x, y, color.NRGBA{})
				continue
			}
			canvas.SetNRGBA(x, y, color.NRGBA{
				uint8(premultiplied[0] / alpha),
				uint8(premultiplied[1] / alpha),
				uint8(premultiplied[2] / alpha),
				uint8(alpha / count),
			})
		}
	}
	if tiled && canvas.NRGBAAt(0, 0).A != 255 {
		panic("maskable icon must have an opaque background")
	}
	if !tiled && canvas.NRGBAAt(0, 0).A != 0 {
		panic("standard icon must preserve a transparent background")
	}
	return canvas
}

func insidePolygon(value point, polygon []point) bool {
	inside := false
	for current, previous := 0, len(polygon)-1; current < len(polygon); previous, current = current, current+1 {
		a, b := polygon[current], polygon[previous]
		if (a.y > value.y) != (b.y > value.y) && value.x < (b.x-a.x)*(value.y-a.y)/(b.y-a.y)+a.x {
			inside = !inside
		}
	}
	return inside
}

func polygonDistance(value point, polygon []point) float64 {
	distance := math.MaxFloat64
	for current, previous := 0, len(polygon)-1; current < len(polygon); previous, current = current, current+1 {
		distance = math.Min(distance, lineDistance(value, polygon[previous], polygon[current]))
	}
	return distance
}

func lineDistance(value, start, end point) float64 {
	dx, dy := end.x-start.x, end.y-start.y
	t := ((value.x-start.x)*dx + (value.y-start.y)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(value.x-(start.x+t*dx), value.y-(start.y+t*dy))
}
