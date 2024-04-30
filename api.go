// Package cloudns private api functions
package cloudns

import (
	"encoding/json"
	"strings"

	"github.com/go-resty/resty/v2"
)

// this is the communicated api endpoint
const (
	apiurl = "https://apidev.cloudns.net"
)

// this is how we will do requests
func apireq(path string, body interface{}) (*resty.Response, error) {
	fullurl := strings.Join([]string{apiurl, path}, "")
	client := resty.New()
	client.R().SetHeader("Content-Type", "application/json")
	client.R().SetHeader("Accept", "application/json")
	client.R().SetHeader("User-Agent", "github.com/Venkoul99/cloudns-go")
	return client.R().SetBody(body).Post(fullurl)
}

// Apierr we should be able to json.Unmarshal this from an *resty.Response.Body(),
// if there was an API error, see https://www.cloudns.net/wiki/article/45/
type apierr struct {
	Status string `json:"status"`
	Desc   string `json:"statusDescription"`
}

// for some reason cloudns returns zones in a different way then they take them
// they also return two more fields: zone and status, I am not sure yet what to do with them :/
type retzone struct {
	Domain string `json:"name"`
	Ztype  string `json:"type"`
	Master string `json:"master-ip,omitempty"`
}

// this function will check a byte array for the error message from ClouDNS
func checkapierr(d []byte) (string, bool) {
	var status apierr
	err := json.Unmarshal(d, &status)
	if err == nil && status.Status != "Success" && (apierr{}) != status {
		return status.Desc, true
	}
	return "", false
}

// logincheck checks if the credentials work, see https://www.cloudns.net/wiki/article/45/
func (c Apiaccess) logincheck() (*resty.Response, error) {
	const path = "/dns/login.json"
	return apireq(path, c)
}

// availablettl gets the currently available TTL values, see https://www.cloudns.net/wiki/article/153/
func (c Apiaccess) availablettl() (*resty.Response, error) {
	const path = "/dns/get-available-ttl.json"
	return apireq(path, c)
}

// types lists available types from api, see https://www.cloudns.net/wiki/article/157/
type rectypes struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
	Ztype        string `json:"zone-type"`
	Master       string `json:"master-ip,omitempty"`
}

// Availabletype gets the currently available Record-Types
func (r rectypes) availabletype() (*resty.Response, error) {
	const path = "/dns/get-available-record-types.json"
	return apireq(path, r)
}

// reclist lists records for a domain, see https://www.cloudns.net/wiki/article/57/
type reclist struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
	Domain       string `json:"domain-name"`
	Host         string `json:"host,omitempty"`
	Rtype        string `json:"type,omitempty"`
}

// list records
func (r reclist) lsrec() (*resty.Response, error) {
	const path = "/dns/records.json"
	return apireq(path, r)
}

// returning records has the same issue as returning zones
// they come back in a completely different format
// in this case we currently ignore failover, status and dynamicurl_status
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

// zonelist struct to lists zones, see https://www.cloudns.net/wiki/article/50/
type zonelist struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
	Page         int    `json:"page"`
	Hits         int    `json:"rows-per-page"`
	Search       string `json:"search,omitempty"`
	Gid          int    `json:"group-id,omitempty"`
}

// list zones
func (z zonelist) lszone() (*resty.Response, error) {
	const path = "/dns/list-zones.json"
	return apireq(path, z)
}

// createrec stuct to create a record, see https://www.cloudns.net/wiki/article/58/
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

// Read returns the created records (map[string]Returnrec in response)
func (r createrec) read() (*resty.Response, error) {
	// this should give us a list containing this exact record
	listrec := reclist{
		Authid:       r.Authid,
		Subauthid:    r.Subauthid,
		Authpassword: r.Authpassword,
		Rtype:        r.Rtype,
		Host:         r.Host,
	}
	return listrec.lsrec()
}

// create actually creates a record
func (r createrec) create() (*resty.Response, error) {
	const path = "/dns/add-record.json"
	return apireq(path, r)
}

// updaterec is the alternative record struct, used here https://www.cloudns.net/wiki/article/60/
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

// Update updates an existing record
func (r updaterec) update() (*resty.Response, error) {
	const path = "/dns/mod-record.json"
	return apireq(path, r)
}

// Destroy destroys the record
func (r updaterec) destroy() (*resty.Response, error) {
	const path = "/dns/delete-record.json"
	return apireq(path, r)
}

// createzone creates a zone, see https://www.cloudns.net/wiki/article/48/
type createzone struct {
	Authid       int      `json:"auth-id,omitempty"`
	Subauthid    int      `json:"sub-auth-id,omitempty"`
	Authpassword string   `json:"auth-password"`
	Domain       string   `json:"domain-name"`
	Ztype        string   `json:"zone-type"`
	Ns           []string `json:"ns,omitempty"`
	Master       string   `json:"master-ip,omitempty"`
}

// read should return the exact zone from the list
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

// create registers a new DNS zone
func (z createzone) create() (*resty.Response, error) {
	const path = "/dns/register.json"
	return apireq(path, z)
}

// zone update/destroy struct, see https://www.cloudns.net/wiki/article/135/ or https://www.cloudns.net/wiki/article/49/
type zupdate struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
	Domain       string `json:"domain-name"`
}

// Update in this context does not make much sense, but we implement it anyway
func (z createzone) update() (*resty.Response, error) {
	// not sure what this does ...
	// see https://www.cloudns.net/wiki/article/135/
	const path = "/dns/update-zone.json"
	up := zupdate{
		Authid:       z.Authid,
		Subauthid:    z.Subauthid,
		Authpassword: z.Authpassword,
		Domain:       z.Domain,
	}
	return apireq(path, up)
}

// Destroy removes a zone
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
