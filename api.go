// Package cloudns private api functions
package cloudns

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-resty/resty/v2"
)

const (
	apiurl = "https://api.cloudns.net"
)

func apireq(path string, body interface{}) (*resty.Response, error) {
	fullurl := strings.Join([]string{apiurl, path}, "")
	client := resty.New()
	client.R().SetHeader("Content-Type", "application/json")
	client.R().SetHeader("Accept", "application/json")
	client.R().SetHeader("User-Agent", "github.com/ClouDNS/cloudns-go")
	return client.R().SetBody(body).Post(fullurl)
}

type apierr struct {
	Status string `json:"status"`
	Desc   string `json:"statusDescription"`
}

type retzone struct {
	Domain string `json:"name"`
	Ztype  string `json:"type"`
	Master string `json:"master-ip,omitempty"`
	Ns     string `json:"ns,omitempty"`
}

func checkapierr(d []byte) (string, bool) {
	var status apierr
	err := json.Unmarshal(d, &status)
	if err == nil && status.Status != "Success" && (apierr{}) != status {
		return status.Desc, true
	}
	return "", false
}

func (c Apiaccess) logincheck() (*resty.Response, error) {
	const path = "/dns/login.json"
	return apireq(path, c)
}

func (c Apiaccess) availablettl() (*resty.Response, error) {
	const path = "/dns/get-available-ttl.json"
	return apireq(path, c)
}

type nslist struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
	DetailedInfo int    `json:"detailed-info,ommitempty"`
}

func (n nslist) lsns() (*resty.Response, error) {
	const path = "/dns/available-name-servers.json"
	return apireq(path, n)
}

type retns struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type rectypes struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
	Ztype        string `json:"zone-type"`
	Master       string `json:"master-ip,omitempty"`
}

func (r rectypes) availabletype() (*resty.Response, error) {
	const path = "/dns/get-available-record-types.json"
	return apireq(path, r)
}

type reclist struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
	Domain       string `json:"domain-name"`
	Host         string `json:"host,omitempty"`
	Rtype        string `json:"type,omitempty"`
}

func (r reclist) lsrec() (*resty.Response, error) {
	const path = "/dns/records.json"
	return apireq(path, r)
}

type retrec struct {
	ID                 string  `json:"id"`
	Host               string  `json:"host"`
	Rtype              string  `json:"type"`
	TTL                string  `json:"ttl"`
	Record             string  `json:"record"`
	Priority           string  `json:"priority,omitempty"`
	Weight             string  `json:"weight,omitempty"`
	Port               string  `json:"port,omitempty"`
	Frame              string  `json:"frame,omitempty"`
	FrameTitle         string  `json:"frame-title,omitempty"`
	FrameKeywords      string  `json:"frame-keywords,omitempty"`
	FrameDescription   string  `json:"frame-description,omitempty"`
	MobileMeta         int     `json:"mobile-meta,omitempty"`
	SavePath           int     `json:"save-path,omitempty"`
	RedirectType       int     `json:"redirect-type,omitempty"`
	Mail               string  `json:"mail,omitempty"`
	Txt                string  `json:"txt,omitempty"`
	Algorithm          string  `json:"algorithm,omitempty"`
	Fptype             int     `json:"fptype,omitempty"`
	Status             int     `json:"status,omitempty"`
	GeodnsLocation     string  `json:"geodns-location,omitempty"`
	GeodnsCode         string  `json:"geodns-code,omitempty"`
	CaaFlag            string  `json:"caa_flag,omitempty"`
	CaaType            string  `json:"caa_type,omitempty"`
	CaaValue           string  `json:"caa_value,omitempty"`
	TlsaUsage          string  `json:"tlsa_usage,omitempty"`
	TlsaSelector       string  `json:"tlsa_selector,omitempty"`
	TlsaMatchingType   string  `json:"tlsa_matching_type,omitempty"`
	SmimeaUsage        string  `json:"smimea-usage,omitempty"`
	SmimeaSelector     string  `json:"smimea-selector,omitempty"`
	SmimeaMatchingType string  `json:"smimea-matching-type,omitempty"`
	KeyTag             int     `json:"key-tag,omitempty"`
	DigestType         int     `json:"digest-type,omitempty"`
	Order              string  `json:"order,omitempty"`
	Pref               string  `json:"pref,omitempty"`
	Flag               string  `json:"flag,omitempty"`
	Params             string  `json:"params,omitempty"`
	Regexp             string  `json:"regexp,omitempty"`
	Replace            string  `json:"replace,omitempty"`
	CertType           int     `json:"cert-type,omitempty"`
	CertKeyTag         int     `json:"cert-key-tag,omitempty"`
	CertAlgorithm      int     `json:"cert-algorithm,omitempty"`
	LatDeg             float64 `json:"lat-deg,omitempty"`
	LatMin             float64 `json:"lat-min,omitempty"`
	LatSec             float64 `json:"lat-sec,omitempty"`
	LatDir             string  `json:"lat-dir,omitempty"`
	LongDeg            float64 `json:"long-deg,omitempty"`
	LongMin            float64 `json:"long-min,omitempty"`
	LongSec            float64 `json:"long-sec,omitempty"`
	LongDir            string  `json:"long-dir,omitempty"`
	Altitude           string  `json:"altitude,omitempty"`
	Size               string  `json:"size,omitempty"`
	HPrecision         string  `json:"h-precision,omitempty"`
	VPrecision         string  `json:"v-precision,omitempty"`
	CPU                string  `json:"cpu,omitempty"`
	OS                 string  `json:"os,omitempty"`
}

type zonelist struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
	Page         int    `json:"page"`
	Hits         int    `json:"rows-per-page"`
	Search       string `json:"search,omitempty"`
	Gid          int    `json:"group-id,omitempty"`
}

func (z zonelist) lszone() (*resty.Response, error) {
	const path = "/dns/list-zones.json"
	return apireq(path, z)
}

type createrec struct {
	Authid             int     `json:"auth-id,omitempty"`
	Subauthid          int     `json:"sub-auth-id,omitempty"`
	Authpassword       string  `json:"auth-password"`
	Domain             string  `json:"domain-name"`
	Rtype              string  `json:"record-type"`
	TTL                int     `json:"ttl"`
	Host               string  `json:"host"`
	Record             string  `json:"record"`
	Priority           *int    `json:"priority,omitempty"`
	Weight             *int    `json:"weight,omitempty"`
	Port               *int    `json:"port,omitempty"`
	Frame              string  `json:"frame,omitempty"`
	FrameTitle         string  `json:"frame-title,omitempty"`
	FrameKeywords      string  `json:"frame-keywords,omitempty"`
	FrameDescription   string  `json:"frame-description,omitempty"`
	MobileMeta         int     `json:"mobile-meta,omitempty"`
	SavePath           int     `json:"save-path,omitempty"`
	RedirectType       int     `json:"redirect-type,omitempty"`
	Mail               string  `json:"mail,omitempty"`
	Txt                string  `json:"txt,omitempty"`
	Algorithm          int     `json:"algorithm,omitempty"`
	Fptype             int     `json:"fptype,omitempty"`
	Status             int     `json:"status,omitempty"`
	GeodnsLocation     string  `json:"geodns-location,omitempty"`
	GeodnsCode         string  `json:"geodns-code,omitempty"`
	CaaFlag            string  `json:"caa_flag,omitempty"`
	CaaType            string  `json:"caa_type,omitempty"`
	CaaValue           string  `json:"caa_value,omitempty"`
	TlsaUsage          string  `json:"tlsa_usage,omitempty"`
	TlsaSelector       string  `json:"tlsa_selector,omitempty"`
	TlsaMatchingType   string  `json:"tlsa_matching_type,omitempty"`
	SmimeaUsage        string  `json:"smimea-usage,omitempty"`
	SmimeaSelector     string  `json:"smimea-selector,omitempty"`
	SmimeaMatchingType string  `json:"smimea-matching-type,omitempty"`
	KeyTag             int     `json:"key-tag,omitempty"`
	DigestType         int     `json:"digest-type,omitempty"`
	Order              string  `json:"order,omitempty"`
	Pref               string  `json:"pref,omitempty"`
	Flag               string  `json:"flag,omitempty"`
	Params             string  `json:"params,omitempty"`
	Regexp             string  `json:"regexp,omitempty"`
	Replace            string  `json:"replace,omitempty"`
	CertType           int     `json:"cert-type,omitempty"`
	CertKeyTag         int     `json:"cert-key-tag,omitempty"`
	CertAlgorithm      int     `json:"cert-algorithm,omitempty"`
	LatDeg             float64 `json:"lat-deg,omitempty"`
	LatMin             float64 `json:"lat-min,omitempty"`
	LatSec             float64 `json:"lat-sec,omitempty"`
	LatDir             string  `json:"lat-dir,omitempty"`
	LongDeg            float64 `json:"long-deg,omitempty"`
	LongMin            float64 `json:"long-min,omitempty"`
	LongSec            float64 `json:"long-sec,omitempty"`
	LongDir            string  `json:"long-dir,omitempty"`
	Altitude           string  `json:"altitude,omitempty"`
	Size               string  `json:"size,omitempty"`
	HPrecision         string  `json:"h-precision,omitempty"`
	VPrecision         string  `json:"v-precision,omitempty"`
	CPU                string  `json:"cpu,omitempty"`
	OS                 string  `json:"os,omitempty"`
}

func (r createrec) read() (*resty.Response, error) {
	listrec := reclist{
		Authid:       r.Authid,
		Subauthid:    r.Subauthid,
		Authpassword: r.Authpassword,
		Rtype:        r.Rtype,
		Host:         r.Host,
	}
	return listrec.lsrec()
}

func (r createrec) create() (*resty.Response, error) {
	const path = "/dns/add-record.json"
	return apireq(path, r)
}

type updaterec struct {
	Authid             int     `json:"auth-id,omitempty"`
	Subauthid          int     `json:"sub-auth-id,omitempty"`
	Authpassword       string  `json:"auth-password"`
	Domain             string  `json:"domain-name"`
	Rid                int     `json:"record-id"`
	TTL                int     `json:"ttl"`
	Host               string  `json:"host"`
	Record             string  `json:"record"`
	Priority           *int    `json:"priority,omitempty"`
	Weight             *int    `json:"weight,omitempty"`
	Port               *int    `json:"port,omitempty"`
	Frame              string  `json:"frame,omitempty"`
	FrameTitle         string  `json:"frame-title,omitempty"`
	FrameKeywords      string  `json:"frame-keywords,omitempty"`
	FrameDescription   string  `json:"frame-description,omitempty"`
	MobileMeta         int     `json:"mobile-meta,omitempty"`
	SavePath           int     `json:"save-path,omitempty"`
	RedirectType       int     `json:"redirect-type,omitempty"`
	Mail               string  `json:"mail,omitempty"`
	Txt                string  `json:"txt,omitempty"`
	Algorithm          int     `json:"algorithm,omitempty"`
	Fptype             int     `json:"fptype,omitempty"`
	Status             int     `json:"status,omitempty"`
	GeodnsLocation     string  `json:"geodns-location,omitempty"`
	GeodnsCode         string  `json:"geodns-code,omitempty"`
	CaaFlag            string  `json:"caa_flag,omitempty"`
	CaaType            string  `json:"caa_type,omitempty"`
	CaaValue           string  `json:"caa_value,omitempty"`
	TlsaUsage          string  `json:"tlsa_usage,omitempty"`
	TlsaSelector       string  `json:"tlsa_selector,omitempty"`
	TlsaMatchingType   string  `json:"tlsa_matching_type,omitempty"`
	SmimeaUsage        string  `json:"smimea-usage,omitempty"`
	SmimeaSelector     string  `json:"smimea-selector,omitempty"`
	SmimeaMatchingType string  `json:"smimea-matching-type,omitempty"`
	KeyTag             int     `json:"key-tag,omitempty"`
	DigestType         int     `json:"digest-type,omitempty"`
	Order              string  `json:"order,omitempty"`
	Pref               string  `json:"pref,omitempty"`
	Flag               string  `json:"flag,omitempty"`
	Params             string  `json:"params,omitempty"`
	Regexp             string  `json:"regexp,omitempty"`
	Replace            string  `json:"replace,omitempty"`
	CertType           int     `json:"cert-type,omitempty"`
	CertKeyTag         int     `json:"cert-key-tag,omitempty"`
	CertAlgorithm      int     `json:"cert-algorithm,omitempty"`
	LatDeg             float64 `json:"lat-deg,omitempty"`
	LatMin             float64 `json:"lat-min,omitempty"`
	LatSec             float64 `json:"lat-sec,omitempty"`
	LatDir             string  `json:"lat-dir,omitempty"`
	LongDeg            float64 `json:"long-deg,omitempty"`
	LongMin            float64 `json:"long-min,omitempty"`
	LongSec            float64 `json:"long-sec,omitempty"`
	LongDir            string  `json:"long-dir,omitempty"`
	Altitude           string  `json:"altitude,omitempty"`
	Size               string  `json:"size,omitempty"`
	HPrecision         string  `json:"h-precision,omitempty"`
	VPrecision         string  `json:"v-precision,omitempty"`
	CPU                string  `json:"cpu,omitempty"`
	OS                 string  `json:"os,omitempty"`
}

func (r updaterec) update() (*resty.Response, error) {
	const path = "/dns/mod-record.json"
	return apireq(path, r)
}

func (r updaterec) destroy() (*resty.Response, error) {
	const path = "/dns/delete-record.json"
	return apireq(path, r)
}

type createzone struct {
	Authid       int      `json:"auth-id,omitempty"`
	Subauthid    int      `json:"sub-auth-id,omitempty"`
	Authpassword string   `json:"auth-password"`
	Domain       string   `json:"domain-name"`
	Ztype        string   `json:"zone-type"`
	Ns           []string `json:"ns,omitempty"`
	Master       string   `json:"master-ip,omitempty"`
}

func (z createzone) read() (*resty.Response, error) {
	listzone := zonelist{
		Authid:       z.Authid,
		Subauthid:    z.Subauthid,
		Authpassword: z.Authpassword,
		Page:         1,
		Hits:         10,
		Search:       z.Domain,
	}
	return listzone.lszone()
}

func (z createzone) create() (*resty.Response, error) {
	const path = "/dns/register.json"
	return apireq(path, z)
}

type zupdate struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
	Domain       string `json:"domain-name"`
}

func (z createzone) update() (*resty.Response, error) {

	const path = "/dns/update-zone.json"
	up := zupdate{
		Authid:       z.Authid,
		Subauthid:    z.Subauthid,
		Authpassword: z.Authpassword,
		Domain:       z.Domain,
	}
	return apireq(path, up)
}

func (z createzone) destroy() (*resty.Response, error) {
	const path = "/dns/delete.json"
	rm := zupdate{
		Authid:       z.Authid,
		Subauthid:    z.Subauthid,
		Authpassword: z.Authpassword,
		Domain:       z.Domain,
	}
	return apireq(path, rm)
}

type CheckSettings struct {
	LatencyLimit    string     `json:"latency_limit,omitempty"`
	Timeout         string     `json:"timeout,omitempty"`
	HttpRequestType string     `json:"http_request_type,omitempty"`
	Host            string     `json:"host,omitempty"`
	Port            CustomPort `json:"port,omitempty"`
	Path            string     `json:"path,omitempty"`
	Content         string     `json:"content,omitempty"`
	QueryResponse   string     `json:"query_response,omitempty"`
	QueryType       string     `json:"query_type,omitempty"`
}

type Failover struct {
	Domain           string        `json:"domain-name"`
	RecordId         string        `json:"record-id"`
	FailoverType     string        `json:"check_type"`
	CheckSettings    CheckSettings `json:"check_settings"`
	MonitoringRegion string        `json:"monitoring_region,omitempty"`
	CheckPeriod      string        `json:"check_period,omitempty"`
	CheckRegion      string        `json:"checkregion,omitempty"`
	DownEventHandler string        `json:"down_event_handler"`
	UpEventHandler   string        `json:"up_event_handler"`
	MainIP           string        `json:"main_ip"`
	BackupIp1        string        `json:"backup_ip_1,omitempty"`
	BackupIp2        string        `json:"backup_ip_2,omitempty"`
	BackupIp3        string        `json:"backup_ip_3,omitempty"`
	BackupIp4        string        `json:"backup_ip_4,omitempty"`
	BackupIp5        string        `json:"backup_ip_5,omitempty"`
	NotificationMail string        `json:"notification_mail,omitempty"`
}

type ApiFailover struct {
	Domain           string     `json:"domain-name"`
	RecordId         string     `json:"record-id"`
	FailoverType     string     `json:"check_type"`
	DownEventHandler string     `json:"down_event_handler"`
	UpEventHandler   string     `json:"up_event_handler"`
	MainIP           string     `json:"main_ip"`
	BackupIp1        string     `json:"backup_ip_1,omitempty"`
	BackupIp2        string     `json:"backup_ip_2,omitempty"`
	BackupIp3        string     `json:"backup_ip_3,omitempty"`
	BackupIp4        string     `json:"backup_ip_4,omitempty"`
	BackupIp5        string     `json:"backup_ip_5,omitempty"`
	MonitoringRegion string     `json:"monitoring_region,omitempty"`
	Host             string     `json:"host,omitempty"`
	Port             CustomPort `json:"port,omitempty"`
	Path             string     `json:"path,omitempty"`
	Content          string     `json:"content,omitempty"`
	QueryType        string     `json:"query_type,omitempty"`
	QueryResponse    string     `json:"query_response,omitempty"`
	CheckPeriod      string     `json:"check_period,omitempty"`
	NotificationMail string     `json:"notification_mail,omitempty"`
	LatencyLimit     string     `json:"latency_limit,omitempty"`
	Timeout          string     `json:"timeout,omitempty"`
	CheckRegion      string     `json:"checkregion,omitempty"`
	HttpRequestType  string     `json:"http_request_type,omitempty"`
}

type FailoverData struct {
	FailoverType     string        `json:"check_type"`
	DownEventHandler string        `json:"down_event_handler"`
	UpEventHandler   string        `json:"up_event_handler"`
	MainIP           string        `json:"main_ip"`
	BackupIp1        string        `json:"backup_ip_1,omitempty"`
	BackupIp2        string        `json:"backup_ip_2,omitempty"`
	BackupIp3        string        `json:"backup_ip_3,omitempty"`
	BackupIp4        string        `json:"backup_ip_4,omitempty"`
	BackupIp5        string        `json:"backup_ip_5,omitempty"`
	MonitoringRegion string        `json:"monitoring_region,omitempty"`
	CheckSettings    CheckSettings `json:"check_settings"`
	CheckPeriod      string        `json:"check_period,omitempty"`
	NotificationMail string        `json:"notification_mail,omitempty"`
	CheckRegion      string        `json:"checkregion,omitempty"`
}

type ActivateFailover struct {
	Authid           int        `json:"auth-id,omitempty"`
	Subauthid        int        `json:"sub-auth-id,omitempty"`
	Authpassword     string     `json:"auth-password"`
	ID               string     `json:"id"`
	Domain           string     `json:"domain-name"`
	RecordId         string     `json:"record-id"`
	FailoverType     string     `json:"check_type"`
	DownEventHandler string     `json:"down_event_handler"`
	UpEventHandler   string     `json:"up_event_handler"`
	MainIP           string     `json:"main_ip"`
	BackupIp1        string     `json:"backup_ip_1,omitempty"`
	BackupIp2        string     `json:"backup_ip_2,omitempty"`
	BackupIp3        string     `json:"backup_ip_3,omitempty"`
	BackupIp4        string     `json:"backup_ip_4,omitempty"`
	BackupIp5        string     `json:"backup_ip_5,omitempty"`
	MonitoringRegion string     `json:"monitoring_region,omitempty"`
	Host             string     `json:"host,omitempty"`
	Port             CustomPort `json:"port,omitempty"`
	Path             string     `json:"path,omitempty"`
	Content          string     `json:"content,omitempty"`
	QueryType        string     `json:"query_type,omitempty"`
	QueryResponse    string     `json:"query_response,omitempty"`
	CheckPeriod      string     `json:"check_period,omitempty"`
	NotificationMail string     `json:"notification_mail,omitempty"`
	LatencyLimit     string     `json:"latency_limit,omitempty"`
	Timeout          string     `json:"timeout,omitempty"`
	CheckRegion      string     `json:"checkregion,omitempty"`
	HttpRequestType  string     `json:"http_request_type,omitempty"`
}

type DynamicUrl struct {
	Domain   string `json:"domain-name"`
	RecordId string `json:"record-id"`
}

type DynamicUrlRequest struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
	Domain       string `json:"domain-name"`
	RecordId     string `json:"record-id"`
}

type DynamicUrlResponse struct {
	Domain   string `json:"domain-name"`
	RecordId string `json:"record-id"`
	Url      string `json:"url"`
}

// If the PORT is default it is returned as int but if it is not default
// it is returned as string
type CustomPort int

func (cp *CustomPort) UnmarshalJSON(data []byte) error {
	var intPort int
	if err := json.Unmarshal(data, &intPort); err == nil {
		*cp = CustomPort(intPort)
		return nil
	}

	var strPort string
	if err := json.Unmarshal(data, &strPort); err == nil {
		intValue, err := strconv.Atoi(strPort)
		if err != nil {
			return err
		}
		*cp = CustomPort(intValue)
		return nil
	}

	return fmt.Errorf("cannot unmarshal %s into CustomPort", string(data))
}

func (r ActivateFailover) create() (*resty.Response, error) {
	const path = "/dns/failover-activate.json"
	return apireq(path, r)
}

func (r ActivateFailover) update() (*resty.Response, error) {
	const path = "/dns/failover-modify.json"
	return apireq(path, r)
}

func (r ActivateFailover) destroy() (*resty.Response, error) {
	const path = "/dns/failover-deactivate.json"
	return apireq(path, r)
}

func (r ActivateFailover) get() (*resty.Response, error) {
	const path = "/dns/failover-settings.json"
	return apireq(path, r)
}
