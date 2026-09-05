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
	"os"
	"path/filepath"
)

type point struct{ x, y float64 }

type renderOptions struct {
	tiled bool
	scale float64
}

var outerShield = smoothOuterShield()
var innerShield = smoothInnerShield()

func main() {
	check := flag.Bool("check", false, "verify committed icons match the deterministic generator")
	flag.Parse()
	assets := []struct {
		path     string
		generate func() []byte
	}{
		{filepath.Join("web", "public", "haven-app-icon-192.png"), func() []byte { return encodePNG(render(192, renderOptions{scale: 1})) }},
		{filepath.Join("web", "public", "haven-app-icon-512.png"), func() []byte { return encodePNG(render(512, renderOptions{scale: 1})) }},
		{filepath.Join("web", "public", "haven-maskable-icon-512.png"), func() []byte { return encodePNG(render(512, renderOptions{tiled: true, scale: 1})) }},
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
	scale := 1.14
	if size <= 24 {
		scale = 1.18
	}
	return renderOptions{scale: scale}
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
					if insidePolygon(point{px, py}, outerShield) {
						shade = green
					}
					if insidePolygon(point{px, py}, innerShield) {
						shade = shieldFill
					}
					if insideRoundedRect(point{px, py}, 7.6, 7.1, 2.35, 9.8, .7) ||
						insideRoundedRect(point{px, py}, 14.05, 7.1, 2.35, 9.8, .7) ||
						insideRoundedRect(point{px, py}, 9.25, 10.9, 5.5, 2.2, 1.1) {
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

func iconPoint(x, y float64) point {
	return point{x * 512 / 24, y * 512 / 24}
}

func appendQuadratic(values []point, control, end point) []point {
	start := values[len(values)-1]
	for step := 1; step <= 24; step++ {
		t := float64(step) / 24
		inverse := 1 - t
		values = append(values, point{
			x: inverse*inverse*start.x + 2*inverse*t*control.x + t*t*end.x,
			y: inverse*inverse*start.y + 2*inverse*t*control.y + t*t*end.y,
		})
	}
	return values
}

func appendCubic(values []point, firstControl, secondControl, end point) []point {
	start := values[len(values)-1]
	for step := 1; step <= 48; step++ {
		t := float64(step) / 48
		inverse := 1 - t
		values = append(values, point{
			x: inverse*inverse*inverse*start.x + 3*inverse*inverse*t*firstControl.x + 3*inverse*t*t*secondControl.x + t*t*t*end.x,
			y: inverse*inverse*inverse*start.y + 3*inverse*inverse*t*firstControl.y + 3*inverse*t*t*secondControl.y + t*t*t*end.y,
		})
	}
	return values
}

func smoothOuterShield() []point {
	values := []point{iconPoint(11.35, 1.93)}
	values = appendQuadratic(values, iconPoint(12, 1.67), iconPoint(12.65, 1.93))
	values = append(values, iconPoint(20.03, 4.92))
	values = appendQuadratic(values, iconPoint(20.55, 5.13), iconPoint(20.55, 5.69))
	values = append(values, iconPoint(20.55, 11.41))
	values = appendCubic(values, iconPoint(20.55, 16.24), iconPoint(17.47, 19.82), iconPoint(12.55, 21.59))
	values = appendQuadratic(values, iconPoint(12, 21.79), iconPoint(11.45, 21.59))
	values = appendCubic(values, iconPoint(6.53, 19.82), iconPoint(3.45, 16.24), iconPoint(3.45, 11.41))
	values = append(values, iconPoint(3.45, 5.69))
	values = appendQuadratic(values, iconPoint(3.45, 5.13), iconPoint(3.97, 4.92))
	return append(values, iconPoint(11.35, 1.93))
}

func smoothInnerShield() []point {
	values := []point{iconPoint(11.56, 3.63)}
	values = appendQuadratic(values, iconPoint(12, 3.45), iconPoint(12.44, 3.63))
	values = append(values, iconPoint(18.48, 6.08))
	values = appendQuadratic(values, iconPoint(18.85, 6.23), iconPoint(18.85, 6.63))
	values = append(values, iconPoint(18.85, 11.41))
	values = appendCubic(values, iconPoint(18.85, 15.24), iconPoint(16.45, 18.15), iconPoint(12.37, 19.71))
	values = appendQuadratic(values, iconPoint(12, 19.85), iconPoint(11.63, 19.71))
	values = appendCubic(values, iconPoint(7.55, 18.15), iconPoint(5.15, 15.24), iconPoint(5.15, 11.41))
	values = append(values, iconPoint(5.15, 6.63))
	values = appendQuadratic(values, iconPoint(5.15, 6.23), iconPoint(5.52, 6.08))
	return append(values, iconPoint(11.56, 3.63))
}

func insideRoundedRect(value point, x, y, width, height, radius float64) bool {
	x *= 512 / 24
	y *= 512 / 24
	width *= 512 / 24
	height *= 512 / 24
	radius *= 512 / 24
	if value.x < x || value.x > x+width || value.y < y || value.y > y+height {
		return false
	}
	nearestX := max(x+radius, min(value.x, x+width-radius))
	nearestY := max(y+radius, min(value.y, y+height-radius))
	dx, dy := value.x-nearestX, value.y-nearestY
	return dx*dx+dy*dy <= radius*radius
}
