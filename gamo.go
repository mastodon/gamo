package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/discordapp/lilliput"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	DEFAULT_BIND       = "127.0.0.1:8081"
	DEFAULT_KEY        = "0x24FEEDFACEDEADBEEFCAFE"
	MAX_CONTENT_LENGTH = 5242880
	MAX_DIMENSIONS     = 8912
)

var (
	configListenAddr string
	configSharedKey  string
	configDimensions string
)

var EncodeOptions = map[string]map[int]int{
	".jpeg": map[int]int{lilliput.JpegQuality: 85},
	".png":  map[int]int{lilliput.PngCompression: 7},
	".webp": map[int]int{lilliput.WebpQuality: 85},
}

func nextRequestID() string {
	return fmt.Sprintf("%s", uuid.Must(uuid.NewV4()))
}

var log = logrus.New()

var opsPool = sync.Pool{
	New: func() interface{} {
		ops := lilliput.NewImageOps(MAX_DIMENSIONS)
		defer ops.Close()
		return ops
	},
}

func main() {
	log.Out = os.Stdout

	flag.StringVar(&configListenAddr, "bind", DEFAULT_BIND, "Bind address")
	flag.StringVar(&configSharedKey, "key", DEFAULT_KEY, "Shared HMAC secret")
	flag.StringVar(&configDimensions, "dimensions", "", "Which target sizes besides the original one will be accessible (comma-separated)")
	flag.Parse()

	listenAddr := configListenAddr
	sharedKey := []byte(configSharedKey)
	dimensionsMap := map[int64]bool{}

	log.Info("Welcome to Gamo, the image proxy and optimization server")
	log.Info(fmt.Sprintf("Starting on %s...", listenAddr))

	if len(configDimensions) > 0 {
		log.Info("With dimensions: ", configDimensions)

		for _, x := range strings.Split(configDimensions, ",") {
			parsedDimensions, err := strconv.ParseInt(x, 10, 0)

			if err != nil {
				log.Fatal("Unrecognized value in dimensions: ", x)
			}

			dimensionsMap[parsedDimensions] = true
		}
	} else {
		log.Info("Without resizing")
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requestID := nextRequestID()
		requestLog := log.WithFields(logrus.Fields{"request-id": requestID})

		w.Header().Add("X-Request-Id", requestID)

		segments := strings.Split(r.URL.Path, "/")
		dimensions := MAX_DIMENSIONS

		if len(segments) < 3 {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		encodedMAC, encodedImageURL := segments[1], segments[2]

		if len(segments) >= 4 {
			parsedDimensions, err := strconv.ParseInt(segments[3], 10, 0)

			if err != nil || !dimensionsMap[parsedDimensions] {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}

			dimensions = int(parsedDimensions)
		}

		imageURL, err := hex.DecodeString(encodedImageURL)

		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		messageMAC, err := hex.DecodeString(encodedMAC)

		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		mac := hmac.New(sha1.New, sharedKey)
		mac.Write(imageURL)
		expectedMAC := mac.Sum(nil)

		if hmac.Equal(messageMAC, expectedMAC) {
			requestLog = requestLog.WithFields(logrus.Fields{"url": string(imageURL)})
			resp, err := http.Get(string(imageURL))

			if err != nil {
				requestLog.Error(fmt.Sprintf("Error performing request: %s", err))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			defer resp.Body.Close()

			contentLength, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 0)

			if contentLength > MAX_CONTENT_LENGTH {
				requestLog.Error("Image exceeds length limit")
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}

			originalImage, err := ioutil.ReadAll(resp.Body)

			if err != nil {
				requestLog.Error(fmt.Sprintf("Error reading response body: %s", err))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			decoder, err := lilliput.NewDecoder(originalImage)

			if err != nil {
				requestLog.Error(fmt.Sprintf("Error decoding image: %s", err))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			defer decoder.Close()

			header, err := decoder.Header()

			if err != nil {
				requestLog.Error(fmt.Sprintf("Error reading image header: %s", err))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			outputFormat := "." + strings.ToLower(decoder.Description())
			outputPixels := dimensions * dimensions

			var (
				outputWidth  int
				outputHeight int
			)

			if (header.Width() * header.Height()) > outputPixels {
				outputWidth = int(math.Round(math.Sqrt(float64(outputPixels) * (float64(header.Width()) / float64(header.Height())))))
				outputHeight = int(math.Round(math.Sqrt(float64(outputPixels) * (float64(header.Height()) / float64(header.Width())))))
			} else {
				outputWidth = header.Width()
				outputHeight = header.Height()
			}

			outputImage := make([]byte, 50*1024*1024)

			resizeOptions := &lilliput.ImageOptions{
				FileType:             outputFormat,
				Width:                outputWidth,
				Height:               outputHeight,
				ResizeMethod:         lilliput.ImageOpsResize,
				NormalizeOrientation: true,
				EncodeOptions:        EncodeOptions[outputFormat],
			}

			ops := opsPool.Get().(*lilliput.ImageOps)
			defer opsPool.Put(ops)

			outputImage, err = ops.Transform(decoder, resizeOptions, outputImage)

			if err != nil {
				requestLog.Error(fmt.Sprintf("Error transforming image: %s", err))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			k, err := w.Write(outputImage)

			if err != nil {
				requestLog.Error(fmt.Sprintf("Error writing response: %s", err))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			w.Header().Add("Content-Length", strconv.FormatInt(int64(k), 10))
			w.Header().Add("Content-Type", resp.Header.Get("Content-Type"))
			w.Header().Add("Cache-Control", "public, max-age=31536000")
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})

	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
