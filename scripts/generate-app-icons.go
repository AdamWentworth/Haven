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

var outerShield = havenOuterShield()
var outlineShield = havenOutlineShield()
var innerShield = havenInnerShield()
var monogram = havenMonogram()

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
	background := color.RGBA{6, 18, 25, 255}
	outline := color.RGBA{224, 255, 248, 255}
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
						shade = diagonalGradient(px, py, color.RGBA{4, 220, 139, 255}, color.RGBA{5, 181, 220, 255})
					}
					if insidePolygon(point{px, py}, outlineShield) {
						shade = outline
					}
					if insidePolygon(point{px, py}, innerShield) {
						shade = verticalGradient(py, 66, 438, color.RGBA{7, 25, 36, 255}, color.RGBA{5, 34, 46, 255})
					}
					if insidePolygon(point{px, py}, monogram) {
						shade = verticalGradient(py, 122, 390, color.RGBA{86, 235, 164, 255}, color.RGBA{15, 207, 224, 255})
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

func interpolate(start, end color.RGBA, amount float64) color.RGBA {
	amount = max(0, min(amount, 1))
	mix := func(left, right uint8) uint8 {
		return uint8(float64(left) + (float64(right)-float64(left))*amount + .5)
	}
	return color.RGBA{R: mix(start.R, end.R), G: mix(start.G, end.G), B: mix(start.B, end.B), A: mix(start.A, end.A)}
}

func verticalGradient(y, startY, endY float64, start, end color.RGBA) color.RGBA {
	return interpolate(start, end, (y-startY)/(endY-startY))
}

func diagonalGradient(x, y float64, start, end color.RGBA) color.RGBA {
	return interpolate(start, end, .35*x/512+.65*y/512)
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

func havenOuterShield() []point {
	values := []point{iconPoint(12, 1.7)}
	values = appendCubic(values, iconPoint(10.6, 2.85), iconPoint(8.4, 4.05), iconPoint(4.1, 5.12))
	values = appendCubic(values, iconPoint(3.7, 5.22), iconPoint(3.48, 5.58), iconPoint(3.48, 6.02))
	values = append(values, iconPoint(3.48, 10.4))
	values = appendCubic(values, iconPoint(3.48, 15.6), iconPoint(6.35, 19.25), iconPoint(11.58, 21.58))
	values = appendQuadratic(values, iconPoint(12, 21.77), iconPoint(12.42, 21.58))
	values = appendCubic(values, iconPoint(17.65, 19.25), iconPoint(20.52, 15.6), iconPoint(20.52, 10.4))
	values = append(values, iconPoint(20.52, 6.02))
	values = appendCubic(values, iconPoint(20.52, 5.58), iconPoint(20.3, 5.22), iconPoint(19.9, 5.12))
	values = appendCubic(values, iconPoint(15.6, 4.05), iconPoint(13.4, 2.85), iconPoint(12, 1.7))
	return values
}

func havenOutlineShield() []point {
	values := []point{iconPoint(12, 2.9)}
	values = appendCubic(values, iconPoint(10.85, 3.82), iconPoint(8.75, 4.85), iconPoint(5.05, 5.82))
	values = appendCubic(values, iconPoint(4.75, 5.9), iconPoint(4.58, 6.17), iconPoint(4.58, 6.5))
	values = append(values, iconPoint(4.58, 10.4))
	values = appendCubic(values, iconPoint(4.58, 15.05), iconPoint(7.04, 18.22), iconPoint(11.62, 20.47))
	values = appendQuadratic(values, iconPoint(12, 20.66), iconPoint(12.38, 20.47))
	values = appendCubic(values, iconPoint(16.96, 18.22), iconPoint(19.42, 15.05), iconPoint(19.42, 10.4))
	values = append(values, iconPoint(19.42, 6.5))
	values = appendCubic(values, iconPoint(19.42, 6.17), iconPoint(19.25, 5.9), iconPoint(18.95, 5.82))
	values = appendCubic(values, iconPoint(15.25, 4.85), iconPoint(13.15, 3.82), iconPoint(12, 2.9))
	return values
}

func havenInnerShield() []point {
	values := []point{iconPoint(12, 3.14)}
	values = appendCubic(values, iconPoint(10.88, 4.02), iconPoint(8.83, 5.02), iconPoint(5.29, 5.95))
	values = appendCubic(values, iconPoint(5.07, 6.01), iconPoint(4.94, 6.21), iconPoint(4.94, 6.46))
	values = append(values, iconPoint(4.94, 10.4))
	values = appendCubic(values, iconPoint(4.94, 14.86), iconPoint(7.27, 17.88), iconPoint(11.68, 20.06))
	values = appendQuadratic(values, iconPoint(12, 20.22), iconPoint(12.32, 20.06))
	values = appendCubic(values, iconPoint(16.73, 17.88), iconPoint(19.06, 14.86), iconPoint(19.06, 10.4))
	values = append(values, iconPoint(19.06, 6.46))
	values = appendCubic(values, iconPoint(19.06, 6.21), iconPoint(18.93, 6.01), iconPoint(18.71, 5.95))
	values = appendCubic(values, iconPoint(15.17, 5.02), iconPoint(13.12, 4.02), iconPoint(12, 3.14))
	return values
}

func havenMonogram() []point {
	return []point{
		iconPoint(7.55, 7), iconPoint(9.45, 5.92), iconPoint(9.62, 6.02),
		iconPoint(9.62, 10.25), iconPoint(14.38, 10.25), iconPoint(14.38, 6.02),
		iconPoint(14.55, 5.92), iconPoint(16.45, 7), iconPoint(16.58, 7.25),
		iconPoint(16.58, 16.55), iconPoint(16.45, 16.82), iconPoint(14.55, 18.22),
		iconPoint(14.38, 18.45), iconPoint(14.38, 12.55), iconPoint(9.62, 12.55),
		iconPoint(9.62, 18.45), iconPoint(9.45, 18.22), iconPoint(7.55, 16.82),
		iconPoint(7.42, 16.55), iconPoint(7.42, 7.25), iconPoint(7.55, 7),
	}
}
