package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Jeffail/tunny"
	"github.com/discord/lilliput"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	DEFAULT_BIND       = "127.0.0.1:8081"
	DEFAULT_KEY        = "0x24FEEDFACEDEADBEEFCAFE"
	MAX_CONTENT_LENGTH = 5242880
	MAX_DIMENSIONS     = 8912
	OUTPUT_BUFFER_SIZE = 10 * 1024 * 1024
)

type imageOpsWorker struct {
	ops *lilliput.ImageOps
}

type imageOpsPayload struct {
	decoder lilliput.Decoder
	options *lilliput.ImageOptions
}

type imageOpsResult struct {
	result []byte
	err    error
}

func (w *imageOpsWorker) Process(payload interface{}) interface{} {
	log.Debug("Allocating memory for transformation")

	input := payload.(*imageOpsPayload)
	output := make([]byte, OUTPUT_BUFFER_SIZE)

	output, err := w.ops.Transform(input.decoder, input.options, output)

	return &imageOpsResult{
		result: output,
		err:    err,
	}
}

func (w *imageOpsWorker) BlockUntilReady() {
	//
}

func (w *imageOpsWorker) Interrupt() {
	//
}

func (w *imageOpsWorker) Terminate() {
	log.Debug("Shutting down worker")
	w.ops.Close()
}

func newImageOpsWorker() *imageOpsWorker {
	log.Debug("Initializing worker")

	return &imageOpsWorker{
		ops: lilliput.NewImageOps(MAX_DIMENSIONS),
	}
}

var (
	configListenAddr string
	configSharedKey  string
	configDimensions string
)

var EncodeOptions = map[string]map[int]int{
	".jpeg": {lilliput.JpegQuality: 85},
	".png":  {lilliput.PngCompression: 7},
	".webp": {lilliput.WebpQuality: 85},
}

func nextRequestID() string {
	return uuid.New().String()
}

var log = logrus.New()

func main() {
	log.Out = os.Stdout
	log.Level = logrus.DebugLevel

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

	pool := tunny.New(2, func() tunny.Worker {
		return newImageOpsWorker()
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requestID := nextRequestID()
		requestLog := log.WithFields(logrus.Fields{"request-id": requestID})

		w.Header().Set("X-Request-Id", requestID)

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

			originalImage, err := io.ReadAll(resp.Body)

			if err != nil {
				requestLog.Error(fmt.Sprintf("Error reading response body: %s", err))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			decoder, err := lilliput.NewDecoder(originalImage)
			originalImage = nil

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

			resizeOptions := &lilliput.ImageOptions{
				FileType:             outputFormat,
				Width:                outputWidth,
				Height:               outputHeight,
				ResizeMethod:         lilliput.ImageOpsResize,
				NormalizeOrientation: true,
				EncodeOptions:        EncodeOptions[outputFormat],
			}

			result := pool.Process(&imageOpsPayload{
				decoder: decoder,
				options: resizeOptions,
			}).(*imageOpsResult)

			if result.err != nil {
				requestLog.Error(fmt.Sprintf("Error transforming image: %s", err))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			outputImage := result.result

			w.Header().Set("Content-Length", strconv.FormatInt(int64(len(outputImage)), 10))
			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			w.Header().Set("Cache-Control", "public, max-age=31536000")
			w.Header().Set("Expires", time.Now().Add(31536000*time.Second).In(time.UTC).Format("Mon, 02 Jan 2006 15:04:05 GMT"))
			w.Header().Set("Vary", "Accept-Encoding")
			w.Header().Set("Etag", fmt.Sprintf("%d-%x", len(outputImage), sha1.Sum(outputImage)))

			if r.Method != "HEAD" {
				_, err = w.Write(outputImage)

				if err != nil {
					requestLog.Error(fmt.Sprintf("Error writing response: %s", err))
				}
			}
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})

	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
