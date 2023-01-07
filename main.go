package qqNeural

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/disintegration/imaging"
	pigo "github.com/esimov/pigo/core"
	"go.uber.org/zap"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	ApiUrl        = "https://ai.tu.qq.com/trpc.shadow_cv.ai_processor_cgi.AIProcessorCgi/Process"
	ExtraString   = "{\"version\":2}"
	BusiID        = "ai_painting_anime_entry"
	FaceHackSize  = 170
	FaceHackSpace = 200
)

var (
	ImageIsIllegalErr   = errors.New("image is illegal")
	InvalidImageErr     = errors.New("invalid image")
	InvalidCountryErr   = errors.New("invalid country")
	ServiceUpgradingErr = errors.New("service upgrading")
	RateLimitErr        = errors.New("rate limit")
	FaceNotFoundErr     = errors.New("face not found")
	OthersErr           = errors.New("others")
)

type Style struct {
	Clients       []*http.Client
	classifier    *pigo.Pigo
	findFaceMutex sync.Mutex
	faceHackFace  image.Image
	logger        *zap.Logger

	getClient func() *http.Client
}

type Response struct {
	Code   int           `json:"code"`
	Msg    string        `json:"msg"`
	Images []interface{} `json:"images"`
	Faces  []interface{} `json:"faces"`
	Extra  string        `json:"extra"`
}

type Extra struct {
	ImgURLs []string `json:"img_urls"`
	UUID    string   `json:"uuid"`
	Videos  []string `json:"videos"`
}

func NewQQNeuralStyle(proxies []string, cascade, faceHack io.Reader, logger *zap.Logger) (*Style, error) {
	qq := Style{
		logger: logger,
	}
	if qq.logger == nil {
		qq.logger = zap.NewNop()
	}
	for _, proxy := range proxies {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			qq.logger.Error("failed to parse proxy url", zap.Error(err))
			return nil, fmt.Errorf("failed to parse proxy url: %w", err)
		}
		qq.Clients = append(qq.Clients, &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyUrl),
			},
		})
	}

	switch len(qq.Clients) {
	case 0:
		qq.logger.Error("no proxy provided")
		return nil, fmt.Errorf("no proxies provided")
	case 1:
		qq.getClient = func() *http.Client {
			return qq.Clients[0]
		}
	default:
		qq.getClient = func() *http.Client {
			return qq.Clients[rand.Intn(len(qq.Clients))]
		}
	}

	var err error
	qq.faceHackFace, err = jpeg.Decode(faceHack)
	if err != nil {
		qq.logger.Error("failed to decode face hack image", zap.Error(err))
		return nil, err
	}
	qq.faceHackFace = imaging.Resize(qq.faceHackFace, FaceHackSize, FaceHackSize, imaging.Lanczos)

	if cascade != nil {
		cascadeData, err := ioutil.ReadAll(cascade)
		if err != nil {
			qq.logger.Error("failed to read cascade file", zap.Error(err))
			return nil, fmt.Errorf("failed to read cascade file: %w", err)
		}
		qq.classifier, err = pigo.NewPigo().Unpack(cascadeData)
		if err != nil {
			qq.logger.Error("failed to unpack cascade file", zap.Error(err))
			return nil, fmt.Errorf("failed to unpack cascade file: %w", err)
		}
		qq.logger.Info("qq: cascade file loaded")
	}
	return &qq, nil
}

func (qq *Style) setHeaders(req *http.Request, length int) {
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("origin", "https://h5.tu.qq.com")
	if length > 0 {
		req.Header.Set("accept", "application/json")
		req.Header.Set("x-sign-version", "v1")
		req.Header.Set("x-sign-value", fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("https://h5.tu.qq.com%dHQ31X02e", length)))))
	}
}

func (qq *Style) request(img io.Reader, client *http.Client, isRetry ...bool) (string, error) {
	imgBytes, err := io.ReadAll(img)
	if err != nil {
		qq.logger.Error("failed to read image", zap.Error(err))
		return "", err
	}

	var payload []byte
	payload, err = json.Marshal(map[string]interface{}{
		"busiId": BusiID,
		"extra":  ExtraString,
		"images": []string{base64.StdEncoding.EncodeToString(imgBytes)},
	})
	if err != nil {
		qq.logger.Error("failed to marshal payload", zap.Error(err))
		return "", err
	}

	var req *http.Request
	req, err = http.NewRequest(
		http.MethodPost,
		ApiUrl,
		bytes.NewBuffer(payload),
	)
	if err != nil {
		qq.logger.Error("failed to create request", zap.Error(err))
		return "", err
	}
	qq.setHeaders(req, len(payload))

	var resp *http.Response
	resp, err = client.Do(req)
	if err != nil {
		proxy := client.Transport.(*http.Transport).Proxy
		if proxy != nil {
			proxyUrl, _ := proxy(req)
			qq.logger.Error("failed to send request2", zap.Error(err), zap.String("proxy", proxyUrl.String()))
		} else {
			qq.logger.Error("failed to send request2", zap.Error(err))
		}
		return "", err
	}
	defer resp.Body.Close()

	var response Response
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		qq.logger.Error("failed to decode response", zap.Error(err))
		return "", err
	}

	switch response.Msg {
	case "VOLUMN_LIMIT":
		return "", RateLimitErr
	case "IMG_ILLEGAL":
		return "", ImageIsIllegalErr
	}

	switch response.Code {
	case 1001:
		if len(isRetry) > 0 {
			return "", FaceNotFoundErr
		}
		faceHackImg, err := qq.FaceHack(bytes.NewBuffer(imgBytes))
		if err != nil {
			return "", err
		}
		return qq.request(faceHackImg, client, true)
	case -2100: // request image is invalid
		return "", InvalidImageErr
	case 2119: // user_ip_country
		return "", InvalidCountryErr
	case -2111: // service upgrading
		return "", ServiceUpgradingErr
	case -2110: // can't get bypass result from redis:
		return "", OthersErr
	case 2114: // b'input img illegal'
		return "", ImageIsIllegalErr
	}

	if response.Code != 0 || response.Msg != "" {
		qq.logger.Error("unknown error", zap.Any("response", response))
		if response.Extra == "" {
			return "", fmt.Errorf("unknown error")
		}
	}

	var extra Extra
	err = json.Unmarshal([]byte(response.Extra), &extra)
	if err != nil {
		qq.logger.Error("failed to unmarshal extra", zap.Error(err), zap.String("extra", response.Extra))
		return "", err
	}

	if len(extra.ImgURLs) < 4 {
		qq.logger.Error("invalid image urls", zap.Int("length", len(extra.ImgURLs)))
		return "", fmt.Errorf("image url not found")
	}
	return extra.ImgURLs[2], nil
}

func (qq *Style) Process(img io.Reader) (io.Reader, error) {
	client := qq.getClient()
	data, err := ioutil.ReadAll(img)
	if err != nil {
		return nil, err
	}

	if qq.classifier != nil && !qq.findFaces(bytes.NewBuffer(data)) {
		faceHackImg, err := qq.FaceHack(bytes.NewBuffer(data))
		if err != nil {
			return nil, err
		}
		data, err = ioutil.ReadAll(faceHackImg)
		if err != nil {
			return nil, err
		}
	}

	imgUrl, err := qq.request(bytes.NewBuffer(data), client)
	if err != nil {
		return nil, err
	}
	var qqImg io.Reader
	qqImg, err = qq.downloadImage(imgUrl, client)
	if err != nil {
		return nil, err
	}

	return qq.cropImage(qqImg)
}

func (qq *Style) downloadImage(url string, client *http.Client) (io.Reader, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		qq.logger.Error("failed to create request", zap.Error(err))
		return nil, err
	}
	qq.setHeaders(req, 0)

	var resp *http.Response
	resp, err = client.Do(req)
	if err != nil {
		proxy := client.Transport.(*http.Transport).Proxy
		if proxy != nil {
			proxyUrl, _ := proxy(req)
			qq.logger.Error("failed to send request2", zap.Error(err), zap.String("proxy", proxyUrl.String()))
		} else {
			qq.logger.Error("failed to send request2", zap.Error(err))
		}
		return nil, err
	}
	defer resp.Body.Close()
	var img []byte
	img, err = io.ReadAll(resp.Body)
	if err != nil {
		qq.logger.Error("failed to read image", zap.Error(err))
		return nil, err
	}
	return bytes.NewReader(img), nil
}

func (qq *Style) cropImage(img io.Reader) (io.Reader, error) {
	imgBytes, err := io.ReadAll(img)
	if err != nil {
		qq.logger.Error("failed to read image", zap.Error(err))
		return nil, err
	}

	var imgDecoded image.Image
	imgDecoded, _, err = image.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		qq.logger.Error("failed to decode image", zap.Error(err))
		return nil, err
	}

	imgWidth := imgDecoded.Bounds().Max.X
	imgHeight := imgDecoded.Bounds().Max.Y
	var cropLeft, cropTop, cropRight, cropBottom, cropWidth, cropHeight int

	if imgWidth > imgHeight {
		cropLeft = 19
		cropTop = 19
		cropRight = 22
		cropBottom = 202
	} else {
		cropLeft = 27
		cropTop = 29
		cropRight = 30
		cropBottom = 213
	}
	cropWidth = imgWidth - cropLeft - cropRight
	cropHeight = imgHeight - cropTop - cropBottom
	cropRect := image.Rect(cropLeft, cropTop, cropLeft+cropWidth, cropTop+cropHeight)
	imgCropped := imaging.Crop(imgDecoded, cropRect)

	imgCroppedBytes := new(bytes.Buffer)
	err = jpeg.Encode(imgCroppedBytes, imgCropped, nil)
	if err != nil {
		qq.logger.Error("failed to encode image", zap.Error(err))
		return nil, err
	}

	return imgCroppedBytes, nil
}

func (qq *Style) FaceHack(srcImg io.Reader) (io.Reader, error) {
	srcImgBytes, err := io.ReadAll(srcImg)
	if err != nil {
		qq.logger.Error("failed to read image", zap.Error(err))
		return nil, err
	}

	var srcImgDecoded image.Image
	srcImgDecoded, _, err = image.Decode(bytes.NewReader(srcImgBytes))
	if err != nil {
		qq.logger.Error("failed to decode image", zap.Error(err))
		return nil, err
	}

	srcImgWidth := srcImgDecoded.Bounds().Max.X
	srcImgHeight := srcImgDecoded.Bounds().Max.Y

	imgWidth, imgHeight := srcImgWidth, srcImgHeight

	if srcImgHeight > srcImgWidth {
		ratio := float64(srcImgHeight) / float64(srcImgWidth)
		if ratio > 1.5 {
			imgHeight = int(math.Floor(float64(srcImgWidth) * 1.5))
		} else {
			imgWidth = int(math.Floor(float64(srcImgHeight) / 1.5))
		}
	} else {
		ratio := float64(srcImgWidth) / float64(srcImgHeight)
		if ratio > 1.5 {
			imgWidth = int(math.Floor(float64(srcImgHeight) * 1.5))
		} else {
			imgHeight = int(math.Floor(float64(srcImgWidth) / 1.5))
		}
	}

	imgWidth = int(math.Max(float64(imgWidth), FaceHackSize))
	imgHeight = int(math.Max(float64(imgHeight), FaceHackSize))
	srcImgDecoded = imaging.Fill(srcImgDecoded, imgWidth, imgHeight, imaging.Center, imaging.Lanczos)

	var img image.Image
	if imgHeight > imgWidth {
		img = imaging.New(imgWidth, imgHeight+FaceHackSize*2+FaceHackSpace*2, color.RGBA{R: 255, G: 255, B: 255})
		img = imaging.Paste(img, srcImgDecoded, image.Pt(0, FaceHackSize+FaceHackSpace))
		img = imaging.Paste(img, qq.faceHackFace, image.Pt(int(math.Round(float64(imgWidth/2.0-FaceHackSize/2.0))), 0))
		img = imaging.Paste(img, qq.faceHackFace, image.Pt(int(math.Round(float64(imgWidth/2.0-FaceHackSize/2.0))), imgHeight+FaceHackSize+FaceHackSpace*2))
	} else {
		img = imaging.New(imgWidth+FaceHackSize*2+FaceHackSpace*2, imgHeight, color.RGBA{R: 255, G: 255, B: 255})
		img = imaging.Paste(img, srcImgDecoded, image.Pt(FaceHackSize+FaceHackSpace, 0))
		img = imaging.Paste(img, qq.faceHackFace, image.Pt(0, int(math.Round(float64(imgHeight/2.0-FaceHackSize/2.0)))))
		img = imaging.Paste(img, qq.faceHackFace, image.Pt(imgWidth+FaceHackSize+FaceHackSpace*2, int(math.Round(float64(imgHeight/2.0-FaceHackSize/2.0)))))
	}

	imgBytes := new(bytes.Buffer)
	err = jpeg.Encode(imgBytes, img, nil)
	if err != nil {
		qq.logger.Error("failed to encode image", zap.Error(err))
		return nil, err
	}
	return imgBytes, nil
}

func (qq *Style) findFaces(img io.Reader) bool {
	src, err := pigo.DecodeImage(img)
	if err != nil {
		qq.logger.Error("failed to decode image", zap.Error(err))
		return false
	}
	cols, rows := src.Bounds().Max.X, src.Bounds().Max.Y
	return len(qq.clusterDetection(pigo.RgbToGrayscale(src), rows, cols)) > 0
}

func (qq *Style) clusterDetection(pixels []uint8, rows, cols int) []pigo.Detection {
	cParams := pigo.CascadeParams{
		MinSize:     100,
		MaxSize:     600,
		ShiftFactor: 0.15,
		ScaleFactor: 1.1,
		ImageParams: pigo.ImageParams{
			Pixels: pixels,
			Rows:   rows,
			Cols:   cols,
			Dim:    cols,
		},
	}
	qq.findFaceMutex.Lock()
	defer qq.findFaceMutex.Unlock()
	dets := qq.classifier.RunCascade(cParams, 0.0)
	return qq.classifier.ClusterDetections(dets, 0.2)
}
