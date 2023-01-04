package main

import (
	qqNeural "github.com/morzik45/go-qq-neural-anime"
	"io"
	"os"
	"strings"
)

func main() {
	proxies := strings.Split(os.Getenv("PROXIES"), ",")
	qq, err := qqNeural.NewQQNeuralStyle(proxies)
	if err != nil {
		panic(err)
	}

	img, err := os.Open("example/img.jpg")
	if err != nil {
		panic(err)
	}

	newImg, err := qq.Process(img)
	if err != nil {
		panic(err)
	}

	out, _ := os.Create("example/qqImg.jpg")
	defer out.Close()

	_, err = io.Copy(out, newImg)
	if err != nil {
		panic(err)
	}
}
