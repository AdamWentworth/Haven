//go:build ignore

// Generate HAVEN's deterministic PWA raster icons from the same simple shield
// geometry as the bundled SVG. It uses only the Go standard library.
package main

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"strconv"
)

type point struct{ x, y float64 }

var shield = []point{
	{256, 64}, {416, 130}, {416, 246}, {409, 292}, {390, 337}, {357, 376},
	{312, 413}, {256, 436}, {200, 413}, {155, 376}, {122, 337}, {103, 292},
	{96, 246}, {96, 130},
}

func main() {
	for _, size := range []int{192, 512} {
		path := filepath.Join("web", "public", "haven-app-icon-"+strconv.Itoa(size)+".png")
		file, err := os.Create(path)
		if err != nil {
			panic(err)
		}
		if err := png.Encode(file, render(size)); err != nil {
			file.Close()
			panic(err)
		}
		if err := file.Close(); err != nil {
			panic(err)
		}
	}
}

func render(size int) *image.RGBA {
	const samples = 4
	large := size * samples
	canvas := image.NewRGBA(image.Rect(0, 0, size, size))
	background := color.RGBA{8, 16, 13, 255}
	shieldFill := color.RGBA{16, 37, 29, 255}
	green := color.RGBA{115, 226, 167, 255}
	pale := color.RGBA{223, 245, 232, 255}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var totals [4]int
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					px := (float64(x*samples+sx) + .5) * 512 / float64(large)
					py := (float64(y*samples+sy) + .5) * 512 / float64(large)
					shade := background
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
					totals[0] += int(shade.R)
					totals[1] += int(shade.G)
					totals[2] += int(shade.B)
					totals[3] += int(shade.A)
				}
			}
			count := samples * samples
			canvas.SetRGBA(x, y, color.RGBA{uint8(totals[0] / count), uint8(totals[1] / count), uint8(totals[2] / count), uint8(totals[3] / count)})
		}
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
