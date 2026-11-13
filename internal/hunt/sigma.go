package hunt

import (
	"crypto/sha1"
	_ "embed"
	"fmt"
	"io"
	"text/template"
	"time"

	"github.com/ryankshah/jackproof/internal/config"
)

//go:embed sigma.tmpl
var sigmaTemplate string

type sigmaValues struct {
	EnableThenInvokeWindow string
	VolumePeriod           string
	MinRequests            int
	DistinctIPWindow       string
	DistinctIPs            int
	KeyUseWindow           string
	ReconWindow            string
	StreamWindow           string
	StreamConcurrency      int
}

func ExportSigma(w io.Writer, settings config.Hunt) error {
	parsed, err := template.New("sigma").Funcs(template.FuncMap{"uuid": sigmaUUID}).Parse(sigmaTemplate)
	if err != nil {
		return fmt.Errorf("parse sigma template: %w", err)
	}
	values := sigmaValues{
		EnableThenInvokeWindow: sigmaDuration(settings.EnableThenInvokeWindow),
		VolumePeriod:           sigmaDuration(settings.VolumePeriod),
		MinRequests:            settings.MinRequests,
		DistinctIPWindow:       sigmaDuration(settings.DistinctIPWindow),
		DistinctIPs:            settings.DistinctIPs,
		KeyUseWindow:           sigmaDuration(settings.KeyUseWindow),
		ReconWindow:            sigmaDuration(settings.ReconWindow),
		StreamWindow:           sigmaDuration(settings.StreamWindow),
		StreamConcurrency:      settings.StreamConcurrency,
	}
	if err := parsed.Execute(w, values); err != nil {
		return fmt.Errorf("render sigma rules: %w", err)
	}
	return nil
}

func sigmaDuration(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}

func sigmaUUID(name string) string {
	sum := sha1.Sum([]byte("jackproof:" + name))
	sum[6] = sum[6]&0x0f | 0x50
	sum[8] = sum[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
