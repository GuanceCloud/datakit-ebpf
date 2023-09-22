package httpflow

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/GuanceCloud/datakit-ebpf/internal/k8sinfo"
	"github.com/GuanceCloud/datakit-ebpf/internal/netflow"
	"github.com/GuanceCloud/datakit-ebpf/internal/tracing"
	"github.com/GuanceCloud/datakit-ebpf/pkg/spanid"
	client "github.com/influxdata/influxdb1-client/v2"
	"github.com/spf13/cast"
)

var k8sNetInfo *k8sinfo.K8sNetInfo

func SetK8sNetInfo(n *k8sinfo.K8sNetInfo) {
	k8sNetInfo = n
}

//nolint:stylecheck
const (
	HTTP_METHOD_UNKNOWN = 0x00 + iota
	HTTP_METHOD_GET
	HTTP_METHOD_POST
	HTTP_METHOD_PUT
	HTTP_METHOD_DELETE
	HTTP_METHOD_HEAD
	HTTP_METHOD_OPTIONS
	HTTP_METHOD_PATCH

	// TODO parse such HTTP data.
	HTTP_METHOD_CONNECT
	HTTP_METHOD_TRACE
)

func HTTPMethodInt(method int) string {
	switch method {
	case HTTP_METHOD_GET:
		return "GET"
	case HTTP_METHOD_POST:
		return "POST"
	case HTTP_METHOD_PUT:
		return "PUT"
	case HTTP_METHOD_DELETE:
		return "DELETE"
	case HTTP_METHOD_HEAD:
		return "HEAD"
	case HTTP_METHOD_OPTIONS:
		return "OPTIONS"
	case HTTP_METHOD_PATCH:
		return "PATCH"
	default:
		return ""
	}
}

func HTTPMethodString(method string) int {
	switch method {
	case "GET":
		return HTTP_METHOD_GET
	case "POST":
		return HTTP_METHOD_POST
	case "PUT":
		return HTTP_METHOD_PUT
	case "DELETE":
		return HTTP_METHOD_DELETE
	case "HEAD":
		return HTTP_METHOD_HEAD
	case "OPTIONS":
		return HTTP_METHOD_OPTIONS
	case "PATCH":
		return HTTP_METHOD_PATCH
	default:
		return HTTP_METHOD_UNKNOWN
	}
}

func FindHTTPURI(payload string) (string, bool) {
	var pathTrunc bool
	split := strings.Split(payload, " ")

	if len(split) < 2 {
		return "", pathTrunc
	}

	if len(split) == 2 {
		pathTrunc = true
	}

	if HTTPMethodString(split[0]) == HTTP_METHOD_UNKNOWN {
		return "", pathTrunc
	}
	uri := split[1]
	startOffset := -1

	switch {
	case len(uri) > 8 && (uri[:8] == "https://"):
		off := strings.Index(uri[8:], "/")
		if off == -1 {
			if strings.Contains(uri, "?") {
				pathTrunc = false
			}
			return "/", pathTrunc
		}
		startOffset = 8 + off
	case len(uri) > 7 && (uri[:7] == "http://"):
		off := strings.Index(uri[7:], "/")
		if off == -1 {
			if strings.Contains(uri, "?") {
				pathTrunc = false
			}
			return "/", pathTrunc
		}
		startOffset = 7 + off
	case (len(uri) > 0) && (uri[:1] == "/"):
		startOffset = 0
	}

	if startOffset == -1 {
		return "", pathTrunc
	}

	endOffset := strings.Index(uri, "?")
	if endOffset > 0 && startOffset < endOffset {
		pathTrunc = false
		return uri[startOffset:endOffset], pathTrunc
	}
	return uri[startOffset:], pathTrunc
}

func ParseHTTPVersion(v uint32) string {
	return fmt.Sprintf("%d.%d", v>>16, v&0xFFFF)
}

func ConnNotNeedToFilter(conn ConnectionInfo) bool {
	if (conn.Saddr[0]|conn.Saddr[1]|conn.Saddr[2]|conn.Saddr[3]) == 0 ||
		(conn.Daddr[0]|conn.Daddr[1]|conn.Daddr[2]|conn.Daddr[3]) == 0 ||
		conn.Sport == 0 || conn.Dport == 0 {
		return false
	}
	if netflow.ConnAddrIsIPv4(conn.Meta) { // IPv4
		if (conn.Saddr[3]&0xff) == 127 && (conn.Daddr[3]&0xff) == 127 {
			return false
		}
	} else { // IPv6
		if conn.Saddr[2] == 0xffff0000 && conn.Daddr[2] == 0xffff0000 {
			if (conn.Saddr[3]&0xff) == 127 && (conn.Daddr[3]&0xff) == 127 {
				return false
			}
		} else if (conn.Saddr[0]|conn.Saddr[1]|conn.Saddr[2]) == 0 && conn.Saddr[3] == 1 &&
			(conn.Daddr[0]|conn.Daddr[1]|conn.Daddr[2]) == 0 && conn.Daddr[3] == 1 {
			return false
		}
	}
	return true
}

func CreateTracePoint(traceInfo *tracing.TraceInfo, httpStat *HTTPReqFinishedInfo) (*client.Point, error) {
	var threadTraceID int64
	var reqSeq int64
	var respSeq int64

	threadTraceID = int64(traceInfo.ThrTraceid)
	reqSeq = httpStat.HTTPStats.ReqSeq
	respSeq = httpStat.HTTPStats.RespSeq

	direction := httpStat.HTTPStats.Direction

	spanType := traceInfo.ESpanType

	var aSampled int64

	if traceInfo.ASpanSampled {
		aSampled = 1
	} else {
		aSampled = -1
	}

	msg, _ := json.Marshal(map[string]any{
		"http_headers": traceInfo.Headers,
		"http_param":   traceInfo.Param,
	})

	fields := map[string]interface{}{
		spanid.EBPFSpanType: spanType,
		spanid.Direction:    direction,
		spanid.ThrTraceID:   threadTraceID,
		spanid.ReqSeq:       reqSeq,
		spanid.RespSeq:      respSeq,

		"source_type": "web",

		"process_name": traceInfo.ProcessName,
		"thread_name":  traceInfo.TaskComm,
		"service":      traceInfo.Service,
		"resource":     traceInfo.Method + " " + traceInfo.Path,

		"http_status_code": cast.ToString(httpStat.HTTPStats.RespCode),
		"http_method":      traceInfo.Method,
		"http_route":       traceInfo.Path,
		"operation":        "HTTP",
		"pid":              int64(traceInfo.PidTid >> 32),
		"span_type":        "local",
		"start":            traceInfo.TS / 1000,
		"duration":         int64(httpStat.HTTPStats.RespTS-httpStat.HTTPStats.ReqTS) / 1000,
		"status":           httpCode2Status(int(httpStat.HTTPStats.RespCode)),
		"recv_bytes":       httpStat.HTTPStats.Recv,
		"send_bytes":       httpStat.HTTPStats.Send,
		"message":          string(msg),
	}

	if traceInfo.HaveTracID {
		var aTraceIDLow int64
		var aTraceIDHigh int64
		var aParentID int64

		// do not change any bits
		aTraceIDLow = int64(traceInfo.TraceID.Low)
		aTraceIDHigh = int64(traceInfo.TraceID.High)
		aParentID = int64(traceInfo.ParentSpanID)

		fields[spanid.AppTraceIDL] = aTraceIDLow
		fields[spanid.AppTraceIDH] = aTraceIDHigh
		fields[spanid.AppParentIDL] = aParentID
		fields[spanid.AppSpanSampled] = aSampled

		var atraceidstr, aparentidstr string
		if traceInfo.HexEncode {
			atraceidstr = traceInfo.TraceID.StringHex()
			aparentidstr = traceInfo.ParentSpanID.StringHex()
			fields[spanid.AppTraceEncode] = "hex"
		} else {
			atraceidstr = traceInfo.TraceID.StringDec()
			aparentidstr = traceInfo.ParentSpanID.StringDec()
			fields[spanid.AppTraceEncode] = "dec"
		}

		fields["app_trace_id"] = atraceidstr
		fields["app_parent_id"] = aparentidstr
	}

	if pt, err := client.NewPoint("ebpf", nil, fields, time.Unix(0, traceInfo.TS)); err != nil {
		return nil, err
	} else {
		return pt, nil
	}
}

func httpCode2Status(code int) string {
	switch {
	case code < 400:
		return "ok"
	case code >= 400 && code < 500:
		return "warning"
	case code >= 500:
		return "error"
	default:
		return ""
	}
}
