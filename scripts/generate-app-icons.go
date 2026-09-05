//go:build ignore

// Generate HAVEN's deterministic raster and Windows icon assets from the same
// simple shield geometry as the bundled SVG. It uses only the Go standard library.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

type point struct{ x, y float64 }

type renderOptions struct {
	tiled       bool
	scale       float64
	strokeWidth float64
}

var shield = []point{
	{256, 64}, {416, 130}, {416, 246}, {409, 292}, {390, 337}, {357, 376},
	{312, 413}, {256, 436}, {200, 413}, {155, 376}, {122, 337}, {103, 292},
	{96, 246}, {96, 130},
}

func main() {
	check := flag.Bool("check", false, "verify committed icons match the deterministic generator")
	flag.Parse()
	assets := []struct {
		path     string
		generate func() []byte
	}{
		{filepath.Join("web", "public", "haven-app-icon-192.png"), func() []byte { return encodePNG(render(192, renderOptions{scale: 1, strokeWidth: 14})) }},
		{filepath.Join("web", "public", "haven-app-icon-512.png"), func() []byte { return encodePNG(render(512, renderOptions{scale: 1, strokeWidth: 14})) }},
		{filepath.Join("web", "public", "haven-maskable-icon-512.png"), func() []byte { return encodePNG(render(512, renderOptions{tiled: true, scale: 1, strokeWidth: 14})) }},
		{filepath.Join("desktop", "build", "icon.png"), func() []byte { return encodePNG(render(512, desktopRenderOptions(512))) }},
		{filepath.Join("desktop", "build", "icon.ico"), encodeWindowsIcon},
	}
	for _, asset := range assets {
		generated := asset.generate()
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

func encodePNG(value image.Image) []byte {
	var output bytes.Buffer
	if err := png.Encode(&output, value); err != nil {
		panic(err)
	}
	return output.Bytes()
}

func desktopRenderOptions(size int) renderOptions {
	strokeWidth := 16.0
	if size <= 24 {
		strokeWidth = 28
	} else if size <= 48 {
		strokeWidth = 22
	}
	return renderOptions{scale: 1.18, strokeWidth: strokeWidth}
}

func render(size int, options renderOptions) *image.NRGBA {
	samples := 4
	if size <= 32 {
		samples = 8
	}
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
					canvasX := (float64(x*samples+sx) + .5) * 512 / float64(large)
					canvasY := (float64(y*samples+sy) + .5) * 512 / float64(large)
					px := 256 + (canvasX-256)/options.scale
					py := 256 + (canvasY-256)/options.scale
					shade := color.RGBA{}
					if options.tiled {
						shade = background
					}
					if insidePolygon(point{px, py}, shield) {
						shade = shieldFill
					}
					if polygonDistance(point{px, py}, shield) <= options.strokeWidth {
						shade = green
					}
					if lineDistance(point{px, py}, point{188, 170}, point{188, 342}) <= options.strokeWidth ||
						lineDistance(point{px, py}, point{324, 170}, point{324, 342}) <= options.strokeWidth ||
						lineDistance(point{px, py}, point{188, 256}, point{324, 256}) <= options.strokeWidth {
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
	if options.tiled && canvas.NRGBAAt(0, 0).A != 255 {
		panic("maskable icon must have an opaque background")
	}
	if !options.tiled && canvas.NRGBAAt(0, 0).A != 0 {
		panic("standard icon must preserve a transparent background")
	}
	return canvas
}

func encodeWindowsIcon() []byte {
	sizes := []int{16, 20, 24, 32, 40, 48, 64, 128, 256}
	images := make([][]byte, 0, len(sizes))
	for _, size := range sizes {
		images = append(images, encodePNG(render(size, desktopRenderOptions(size))))
	}

	var output bytes.Buffer
	mustWrite := func(value any) {
		if err := binary.Write(&output, binary.LittleEndian, value); err != nil {
			panic(err)
		}
	}
	mustWrite(uint16(0))
	mustWrite(uint16(1))
	mustWrite(uint16(len(images)))
	offset := 6 + 16*len(images)
	for index, data := range images {
		dimension := byte(sizes[index])
		if sizes[index] == 256 {
			dimension = 0
		}
		mustWrite(dimension)
		mustWrite(dimension)
		mustWrite(byte(0))
		mustWrite(byte(0))
		mustWrite(uint16(1))
		mustWrite(uint16(32))
		mustWrite(uint32(len(data)))
		mustWrite(uint32(offset))
		offset += len(data)
	}
	for _, data := range images {
		if _, err := output.Write(data); err != nil {
			panic(err)
		}
	}
	return output.Bytes()
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
