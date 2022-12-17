// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// 代理检查 prober
package prober

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func ProbePROXY(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	if len(module.PROXY.CheckUrls) == 0 {
		module.PROXY.CheckUrls = []string{
			"http://1.1.1.1/",
		}
	}

	var (
		// copy http.go
		statusCodeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_http_status_code",
			Help: "Response HTTP status code",
		})
	)

	registry.MustRegister(statusCodeGauge)

	proxyConfig := module.PROXY
	if proxyConfig.Method == "" {
		proxyConfig.Method = "HEAD"
	}

	proxyUrl, err := url.Parse("http://" + target)
	if err != nil {
		level.Error(logger).Log("msg", "Could not parse proxy", "err", err)
		return false
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyUrl),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Second * module.Timeout,
	}

	targetUrl := proxyConfig.CheckUrls[rand.Intn(len(proxyConfig.CheckUrls))]
	request, err := http.NewRequest(proxyConfig.Method, targetUrl, nil)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating request", "err", err)
		return
	}
	request = request.WithContext(ctx)
	resp, err := client.Do(request)
	if resp == nil {
		if err != nil {
			level.Error(logger).Log("msg", "Error for HTTP request", "err", err)
		}
		return
	} else {
		if 200 <= resp.StatusCode && resp.StatusCode < 400 {
			success = true
		} else {
			success = false
		}
		statusCodeGauge.Set(float64(resp.StatusCode))
	}

	return
}
