/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"
	"os"
	"strconv"

	//"github.com/tidwall/gjson"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	//"github.com/http-wasm/http-wasm-guest-tinygo/handler/internal/imports"
)

//var rules []string

// build main like below:
// tinygo version 0.30.0 linux/amd64 (using go version go1.19 and LLVM version 16.0.1)
// tinygo build -o envoy-tests.wasm -scheduler=none --no-debug -target=wasi main.go
func main() {
	// requiredFeatures := api.FeatureBufferRequest | api.FeatureBufferResponse
	// if want, have := requiredFeatures, handler.Host.EnableFeatures(requiredFeatures); !have.IsEnabled(want) {
	// 	panic("unexpected features, want: " + want.String() + ", have: " + have.String())
	// }
	//_ = handler.Host.GetConfig()
	handler.HandleRequestFn = handleRequest
	//handler.HandleResponseFn = HandleResponse
}

// guest can define the context ID, or it can be looked up in host config.
var contextID int
var headerRcvd bool

func handleRequest(req api.Request, resp api.Response) (next bool, reqCtx uint32) {
	contextID++
	//contextID = 5555
	testID, _ := req.Headers().Get("testid")
	if len(testID) == 0 {
		resp.SetStatusCode(500)
		resp.Body().WriteString("missing testid header")
		return false, 0
	}

	switch testID {
	case "headers only with env vars":
		var msg string
		value := os.Getenv("ENVOY_HTTP_WASM_TEST_HEADERS_HOST_ENV")
		if value != "" {
			msg += "ENVOY_HTTP_WASM_TEST_HEADERS_HOST_ENV: " + value
		}
		value = os.Getenv("ENVOY_HTTP_WASM_TEST_HEADERS_KEY_VALUE_ENV")

		if value != "" {
			msg += "\nENVOY_HTTP_WASM_TEST_HEADERS_KEY_VALUE_ENV: " + value
		}
		handler.Host.Log(api.LogLevelInfo, "envs: "+msg)

		req.Headers().Set("Wasm-Context", strconv.Itoa(contextID))
		req.Headers().Set("newheader", "newheadervalue")
		req.Headers().Set("server", "envoy-httpwasm")
		next = true
	case "read body without req buffering":
		if headerRcvd {
			headerRcvd = false
			readBody(req, resp, "read body without req buffering")
			writeBody(req, resp)

			next = true
			return
		}
		headerRcvd = true

		// req.Headers().Set("Wasm-Context", strconv.Itoa(contextID))
		// req.Headers().Set("newheader", "newheadervalue")
		// req.Headers().Set("server", "envoy-httpwasm")
		// requiredFeatures := api.FeatureBufferRequest | api.FeatureBufferResponse
		// if want, have := requiredFeatures, handler.Host.EnableFeatures(requiredFeatures); !have.IsEnabled(want) {
		// 	panic("unexpected features, want: " + want.String() + ", have: " + have.String())
		// }

		next = true
	case "read body":
		if headerRcvd {
			headerRcvd = false
			readBody(req, resp, "read body")
			writeBody(req, resp)

			next = true
			return
		}
		headerRcvd = true

		req.Headers().Set("Wasm-Context", strconv.Itoa(contextID))
		req.Headers().Set("newheader", "newheadervalue")
		req.Headers().Set("server", "envoy-httpwasm")
		requiredFeatures := api.FeatureBufferRequest | api.FeatureBufferResponse
		if want, have := requiredFeatures, handler.Host.EnableFeatures(requiredFeatures); !have.IsEnabled(want) {
			panic("unexpected features, want: " + want.String() + ", have: " + have.String())
		}

		next = true
	default:
		fail(resp, "unknown x-httpwasm-test-id")
	}
	return
}
func readBody(req api.Request, resp api.Response, msg string) {
	for {
		body := make([]byte, 5)
		size, eof := req.Body().Read(body)
		if size > 0 && eof {
			handler.Host.Log(api.LogLevelInfo, msg+": "+string(body[:size])+"; size: "+strconv.Itoa(int(size))+"; eof: "+strconv.FormatBool(eof))
		} else {
			handler.Host.Log(api.LogLevelInfo, msg+": "+string(body)+"; size: "+strconv.Itoa(int(size))+"; eof: "+strconv.FormatBool(eof))
		}
		if eof {
			break
		}
	}
}
func readRespBody(req api.Request, resp api.Response) {
	for {
		body := make([]byte, 500000)
		size, eof := resp.Body().Read(body)
		if size > 0 && eof {
			handler.Host.Log(api.LogLevelInfo, "read-body: "+string(body)+"; size: "+strconv.Itoa(int(size))+"; eof: "+strconv.FormatBool(eof))
		} else {
			handler.Host.Log(api.LogLevelInfo, "read-body: "+string(body)+"; size: "+strconv.Itoa(int(size))+"; eof: "+strconv.FormatBool(eof))
		}
		if eof {
			break
		}
	}
}
func writeBody(req api.Request, resp api.Response) (next bool, reqCtx uint32) {
	body := make([]byte, 15)
	bodysrc := []byte("Hello, Mr.GoGo!")
	copy(body, bodysrc)
	req.Body().Write(body)
	//req.Headers().Set("content-length", strconv.Itoa())

	//handler.Host.Log(api.LogLevelInfo, "writebody: "+string(body))
	next = true
	return
}

// HandleResponse implements Middleware.HandleResponse
func HandleResponse(ctx uint32, _ api.Request, res api.Response, err bool) {
	names := res.Headers().Names()
	handler.Host.Log(api.LogLevelInfo, "responseeee header-names: "+fmt.Sprintf("%v", names))
	readRespBody(nil, res)

}

func fail(resp api.Response, msg string) {
	resp.SetStatusCode(500)
	resp.Headers().Set("x-httpwasm-tck-failed", msg)
}
