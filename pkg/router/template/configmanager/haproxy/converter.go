package haproxy

import (
	"bytes"
	"encoding/csv"
	"io"
	"github.com/gocarina/gocsv"
	"github.com/golang/glog"
)

type Converter interface {
	Convert(data []byte) ([]byte, error)
}
type ByteConverterFunc func([]byte) ([]byte, error)
type CSVConverter struct {
	headers		[]byte
	out		interface{}
	converterFunc	ByteConverterFunc
}

func NewCSVConverter(headers string, out interface{}, fn ByteConverterFunc) *CSVConverter {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &CSVConverter{headers: []byte(headers), out: out, converterFunc: fn}
}
func (c *CSVConverter) Convert(data []byte) ([]byte, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(5).Infof("CSV converter input data bytes: %s", string(data))
	if c.converterFunc != nil {
		convertedBytes, err := c.converterFunc(data)
		if err != nil {
			return data, err
		}
		data = convertedBytes
		glog.V(5).Infof("CSV converter transformed data bytes: %s", string(data))
	}
	if c.out == nil {
		return data, nil
	}
	gocsv.SetCSVReader(func(in io.Reader) gocsv.CSVReader {
		r := csv.NewReader(in)
		r.LazyQuotes = true
		r.TrimLeadingSpace = true
		r.Comma = ' '
		return r
	})
	glog.V(5).Infof("CSV converter fixing up csv header ...")
	data, _ = fixupHeaders(data, c.headers)
	glog.V(5).Infof("CSV converter fixed up data bytes: %s", string(data))
	return data, gocsv.Unmarshal(bytes.NewBuffer(data), c.out)
}
func fixupHeaders(data, headers []byte) ([]byte, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	prefix := []byte("#")
	if len(headers) > 0 && !bytes.HasPrefix(data, prefix) {
		line := bytes.Join([][]byte{prefix, headers}, []byte(" "))
		data = bytes.Join([][]byte{line, data}, []byte("\n"))
	}
	return bytes.TrimPrefix(data, prefix), nil
}
