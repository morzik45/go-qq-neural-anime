package qqNeural

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/disintegration/imaging"
	"go.uber.org/zap"
	"image"
	"image/jpeg"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

const (
	ApiUrl      = "https://ai.tu.qq.com/trpc.shadow_cv.ai_processor_cgi.AIProcessorCgi/Process"
	ExtraString = "{\"version\":2}"
	BusiID      = "ai_painting_anime_entry"
)

type Style struct {
	Clients []*http.Client
	logger  *zap.Logger

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

func NewQQNeuralStyle(proxies []string, logger *zap.Logger) (*Style, error) {
	qq := Style{
		logger: logger,
	}
	for _, proxy := range proxies {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			qq.logger.Error("failed to parse proxy url", zap.Error(err))
			return nil, fmt.Errorf("failed to parse proxy url: %w", err)
		}
		qq.Clients = append(qq.Clients, &http.Client{
			Timeout: 20 * time.Second,
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

func (qq *Style) request(img io.Reader, client *http.Client) (string, error) {
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
		qq.logger.Error("failed to send request", zap.Error(err))
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
		qq.logger.Error("volumn limit")
		return "", fmt.Errorf("rate limit exceeded")
	case "IMG_ILLEGAL":
		qq.logger.Error("image illegal")
		return "", fmt.Errorf("image is illegal")
	}

	switch response.Code {
	case 1001:
		qq.logger.Error("invalid busiId")
		return "", fmt.Errorf("face not found")
	case -2100: // request image is invalid
		qq.logger.Error("invalid image")
		return "", fmt.Errorf("image is invalid")
	case 2119: // user_ip_country
		qq.logger.Error("invalid country")
		return "", fmt.Errorf("user ip country")
	case -2111: // service upgrading
		qq.logger.Error("service upgrading")
		return "", fmt.Errorf("service upgrading")
	}

	var extra Extra
	err = json.Unmarshal([]byte(response.Extra), &extra)
	if err != nil {
		qq.logger.Error("failed to unmarshal extra", zap.Error(err))
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
	imgUrl, err := qq.request(img, client)
	if err != nil {
		qq.logger.Error("failed to request", zap.Error(err))
		return nil, err
	}
	var qqImg io.Reader
	qqImg, err = qq.downloadImage(imgUrl, client)
	if err != nil {
		qq.logger.Error("failed to download image", zap.Error(err))
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
		qq.logger.Error("failed to send request", zap.Error(err))
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
		cropTop = 29
		cropLeft = 29
		cropRight = 20
		cropBottom = 195
	}
	cropWidth = imgWidth - cropLeft - cropRight
	cropHeight = imgHeight - cropTop - cropBottom

	imgCropped := imaging.Crop(imgDecoded, image.Rect(cropLeft, cropTop, cropWidth, cropHeight))

	imgCroppedBytes := new(bytes.Buffer)
	err = jpeg.Encode(imgCroppedBytes, imgCropped, nil)
	if err != nil {
		qq.logger.Error("failed to encode image", zap.Error(err))
		return nil, err
	}

	return imgCroppedBytes, nil
}
