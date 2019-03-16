package internal

import (
	"fmt"

	"github.com/harrydb/go/img/grayscale"
	"github.com/nfnt/resize"

	"image"
)

func zip(lists ...[]uint8) func() []uint8 {
	zip := make([]uint8, len(lists))
	i := 0
	return func() []uint8 {
		for j := range lists {
			if i >= len(lists[j]) {
				return nil
			}
			zip[j] = lists[j][i]
		}
		i++
		return zip
	}
}

type AspectRatio struct {
	X uint
	Y uint
}

func doBrailleCode(img image.Gray, r image.Rectangle) error {
	// Read a 2x3 block of the image hopping by two, and
	// move along the width, and then move down three pixels.
	r.Intersect(img.Rect)
	if r.Empty() {
		return fmt.Errorf("The image and the rect don't overlap")
	}

	startY := r.Min.Y
	for y := startY; y < r.Max.Y; y = y + 3 {
		iterator := zip(
			img.Pix[(img.Stride*y)+r.Min.X:(img.Stride*y)+r.Max.X],
			img.Pix[(img.Stride*(y+1))+r.Min.X:(img.Stride*(y+1))+r.Max.X],
			img.Pix[(img.Stride*(y+2))+r.Min.X:(img.Stride*(y+2))+r.Max.X],
		)

		for {
			leftPixels := iterator()
			rightPixels := iterator()
			if leftPixels == nil || rightPixels == nil {
				break
			}

			braileBinary := 0
			for index, pixel := range append(leftPixels, rightPixels...) {
				if pixel > 128 {
					braileBinary = braileBinary | (1 << uint(index))
				}
			}
			fmt.Printf(string(0x2800 + braileBinary))
		}
		fmt.Printf("\n")
		// 1 4
		// 2 5
		// 3 6
	}

	return nil
}

func PrintBraille(src image.Image) error {
	resizedSrc := resize.Resize(
		// uint((srcSize.Max.X-srcSize.Min.X)/150),
		// uint((srcSize.Max.Y-srcSize.Min.Y)/20),
		120, 0,
		src,
		resize.Lanczos3,
	)
	gray := grayscale.Convert(resizedSrc, grayscale.ToGrayLuminance)

	return doBrailleCode(*gray, gray.Rect)
}
