// Package cloudns public structs/functions
package cloudns

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/tidwall/gjson"
)

// Apiaccess ClouDNS API Credentials, see https://www.cloudns.net/wiki/article/42/
type Apiaccess struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
}

// Zone is the external representation of a zone
// check the ...zone types in api.go for details
type Zone struct {
	Domain string   `json:"domain-name"`
	Ztype  string   `json:"zone-type"`
	Ns     []string `json:"ns,omitempty"`
	Master string   `json:"master-ip,omitempty"`
}

// Listzones returns all zones (max: 100)
func (a Apiaccess) Listzones() ([]Zone, error) {
	zls := zonelist{
		Authid:       a.Authid,
		Subauthid:    a.Subauthid,
		Authpassword: a.Authpassword,
		Page:         1,
		Hits:         100,
	}
	resp, err := zls.lszone()
	var rz []Zone
	if err == nil {
		errmsg, isapierr := checkapierr(resp.Body())
		if isapierr {
			return rz, errors.New(errmsg)
		}
		var intrz []retzone
		err2 := json.Unmarshal(resp.Body(), &intrz)
		for _, zn := range intrz {
			tmpzn := Zone{
				Domain: zn.Domain,
				Ztype:  zn.Ztype,
			}
			rz = append(rz, tmpzn)
		}
		return rz, err2
	}
	return rz, err
}

// List returns all records from a zone
func (z Zone) List(a *Apiaccess) ([]Record, error) {
	var ra []Record
	rls := reclist{
		Authid:       a.Authid,
		Subauthid:    a.Subauthid,
		Authpassword: a.Authpassword,
		Domain:       z.Domain,
	}
	resp, err := rls.lsrec()
	if err == nil {
		errmsg, isapierr := checkapierr(resp.Body())
		if isapierr {
			return ra, errors.New(errmsg)
		}
		var ratmp map[string]retrec
		err2 := json.Unmarshal(resp.Body(), &ratmp)
		for _, rec := range ratmp {

			tmpttl, _ := strconv.Atoi(rec.TTL)
			tmppriority, _ := strconv.Atoi(rec.Priority)
			tmpframe := rec.Frame
			tmpframetitle := rec.FrameTitle
			tmpframekeywords := rec.FrameKeywords
			tmpframedescription := rec.FrameDescription
			tmpmobilemeta := rec.MobileMeta
			tmpsavepath := rec.SavePath
			tmpredirecttype := rec.RedirectType
			tmpweight, _ := strconv.Atoi(rec.Weight)
			tmpport, _ := strconv.Atoi(rec.Port)
			tmpmail := rec.Mail
			tmptxt := rec.Txt
			tmpalgorithm, _ := strconv.Atoi(rec.Algorithm)
			tmpfptype := rec.Fptype
			tmpflag := rec.Flag
			tmporder := rec.Order
			tmppref := rec.Pref
			tmpparams := rec.Params
			tmpregexp := rec.Regexp
			tmpreplace := rec.Replace
			tmpcaaflag := rec.CaaFlag
			tmpcaatype := rec.CaaType
			tmpcaavalue := rec.CaaValue
			tmptlsausage := rec.TlsaUsage
			tmptlsaselector := rec.TlsaSelector
			tmptlsamatchingtype := rec.TlsaMatchingType
			tmpkeytag := rec.KeyTag
			tmpdigesttype := rec.DigestType
			tmpcerttype := rec.CertType
			tmpcertkeytag := rec.CertKeyTag
			tmpcertalgorithm := rec.CertAlgorithm
			tmpcpu := rec.CPU
			tmpos := rec.OS
			tmplatdeg := rec.LatDeg
			tmplatmin := rec.LatMin
			tmplatsec := rec.LatSec
			tmplatdir := rec.LatDir
			tmplongdeg := rec.LongDeg
			tmplongmin := rec.LongMin
			tmplongsec := rec.LongSec
			tmplongdir := rec.LongDir
			tmpaltitude := rec.Altitude
			tmpsize := rec.Size
			tmphprecision := rec.HPrecision
			tmpvprecision := rec.VPrecision
			tmpsmimeausage := rec.SmimeaUsage
			tmpsmimeaselector := rec.SmimeaSelector
			tmpsmimeamatchingtype := rec.SmimeaMatchingType
			tmpgeodnscode := rec.GeodnsCode
			tmpgeodnslocation := rec.GeodnsLocation

			rectmp := Record{
				Domain:             z.Domain,
				ID:                 rec.ID,
				Rtype:              rec.Rtype,
				Host:               rec.Host,
				TTL:                tmpttl,
				Record:             rec.Record,
				Priority:           tmppriority,
				Frame:              tmpframe,
				FrameTitle:         tmpframetitle,
				FrameKeywords:      tmpframekeywords,
				FrameDescription:   tmpframedescription,
				MobileMeta:         tmpmobilemeta,
				SavePath:           tmpsavepath,
				RedirectType:       tmpredirecttype,
				Weight:             tmpweight,
				Port:               tmpport,
				Mail:               tmpmail,
				Txt:                tmptxt,
				Algorithm:          tmpalgorithm,
				Fptype:             tmpfptype,
				Flag:               tmpflag,
				Order:              tmporder,
				Pref:               tmppref,
				Params:             tmpparams,
				Regexp:             tmpregexp,
				Replace:            tmpreplace,
				CaaFlag:            tmpcaaflag,
				CaaType:            tmpcaatype,
				CaaValue:           tmpcaavalue,
				TlsaUsage:          tmptlsausage,
				TlsaSelector:       tmptlsaselector,
				TlsaMatchingType:   tmptlsamatchingtype,
				KeyTag:             tmpkeytag,
				DigestType:         tmpdigesttype,
				CertType:           tmpcerttype,
				CertKeyTag:         tmpcertkeytag,
				CertAlgorithm:      tmpcertalgorithm,
				CPU:                tmpcpu,
				OS:                 tmpos,
				LatDeg:             tmplatdeg,
				LatMin:             tmplatmin,
				LatSec:             tmplatsec,
				LatDir:             tmplatdir,
				LongDeg:            tmplongdeg,
				LongMin:            tmplongmin,
				LongSec:            tmplongsec,
				LongDir:            tmplongdir,
				Altitude:           tmpaltitude,
				Size:               tmpsize,
				HPrecision:         tmphprecision,
				VPrecision:         tmpvprecision,
				SmimeaUsage:        tmpsmimeausage,
				SmimeaSelector:     tmpsmimeaselector,
				SmimeaMatchingType: tmpsmimeamatchingtype,
				GeodnsLocation:     tmpgeodnslocation,
				GeodnsCode:         tmpgeodnscode,
			}
			ra = append(ra, rectmp)
		}
		return ra, err2
	}
	return ra, err
}

// Create a new zone
func (z Zone) Create(a *Apiaccess) (Zone, error) {
	cr := createzone{
		Authid:       a.Authid,
		Subauthid:    a.Subauthid,
		Authpassword: a.Authpassword,
		Domain:       z.Domain,
		Ztype:        z.Ztype,
		Ns:           z.Ns,
		Master:       z.Master,
	}
	resp, err := cr.create()
	if err == nil {
		errmsg, isapierr := checkapierr(resp.Body())
		if isapierr {
			return z, errors.New(errmsg)
		}
	}
	return z, err
}

// Read a zone
func (z Zone) Read(a *Apiaccess) (Zone, error) {
	cr := createzone{
		Authid:       a.Authid,
		Subauthid:    a.Subauthid,
		Authpassword: a.Authpassword,
		Domain:       z.Domain,
		Ztype:        z.Ztype,
		Ns:           z.Ns,
		Master:       z.Master,
	}

	resp, err := cr.read()
	if err != nil {
		return z, err
	}

	errmsg, isapierr := checkapierr(resp.Body())
	if isapierr {
		return z, errors.New(errmsg)
	}

	var zlint []retzone
	body := resp.Body()

	if len(body) == 0 {
		return z, errors.New("empty response body")
	}

	junerr := json.Unmarshal(body, &zlint)
	if junerr != nil {
		return z, fmt.Errorf("error unmarshalling response: %v", junerr)
	}

	if len(zlint) == 0 {
		return z, errors.New("no zones returned in response")
	}

	var matchedZone *retzone
	for _, zone := range zlint {
		if zone.Domain == z.Domain {
			matchedZone = &zone
			break
		}
	}

	if matchedZone == nil {
		return z, fmt.Errorf("zone with domain %s not found", z.Domain)
	}

	nsList := []string{matchedZone.Ns}

	rz := Zone{
		Domain: matchedZone.Domain,
		Ztype:  matchedZone.Ztype,
		Ns:     nsList,
	}

	fmt.Printf("Parsed zone: Domain: %s, Type: %s\n", rz.Domain, rz.Ztype)

	return rz, nil
}

// Update a zone [dummy]
func (z Zone) Update(a *Apiaccess) (Zone, error) {
	err := errors.New("Zone updates are currently not implemented, see https://github.com/sta-travel/cloudns-go/limitations.md")
	return z, err
}

// Destroy a zone
func (z Zone) Destroy(a *Apiaccess) (Zone, error) {
	cr := createzone{
		Authid:       a.Authid,
		Subauthid:    a.Subauthid,
		Authpassword: a.Authpassword,
		Domain:       z.Domain,
		Ztype:        z.Ztype,
		Ns:           z.Ns,
		Master:       z.Master,
	}
	resp, err := cr.destroy()
	if err == nil {
		errmsg, isapierr := checkapierr(resp.Body())
		if isapierr {
			return z, errors.New(errmsg)
		}
	}
	return z, err
}

// Record is the external representation of a record
// check the ...record types in api.go for details
type Record struct {
	ID                 string  `json:"id"`
	Domain             string  `json:"domain-name"`
	Host               string  `json:"host"`
	Rtype              string  `json:"record-type"`
	TTL                int     `json:"ttl"`
	Record             string  `json:"record"`
	Priority           int     `json:"priority,omitempty"`
	Weight             int     `json:"weight,omitempty"`
	Port               int     `json:"port,omitempty"`
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
	SmimeaMatchingType string  `json:"smimea-matching_type,omitempty"`
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

// Create a new record
func (r Record) Create(a *Apiaccess) (Record, error) {
	inr := createrec{
		Authid:       a.Authid,
		Subauthid:    a.Subauthid,
		Authpassword: a.Authpassword,
		Domain:       r.Domain,
		Host:         r.Host,
		Rtype:        r.Rtype,
		TTL:          r.TTL,
		Record:       r.Record,
	}

	if r.Rtype == "MX" {
		inr.Priority = &r.Priority
	} else if r.Rtype == "WR" {
		inr.Frame = r.Frame
		inr.FrameTitle = r.FrameTitle
		inr.FrameKeywords = r.FrameKeywords
		inr.FrameDescription = r.FrameDescription
		inr.MobileMeta = r.MobileMeta
		inr.SavePath = r.SavePath
		inr.RedirectType = r.RedirectType
	} else if r.Rtype == "SRV" {
		inr.Priority = &r.Priority
		inr.Weight = &r.Weight
		inr.Port = &r.Port
	} else if r.Rtype == "RP" {
		inr.Mail = r.Mail
		inr.Txt = r.Txt
	} else if r.Rtype == "SSHFP" {
		inr.Algorithm = r.Algorithm
		inr.Fptype = r.Fptype
	} else if r.Rtype == "NAPTR" {
		inr.Flag = r.Flag
		inr.Order = r.Order
		inr.Pref = r.Pref
		inr.Params = r.Params
		inr.Regexp = r.Regexp
		inr.Replace = r.Replace
	} else if r.Rtype == "CAA" {
		inr.CaaFlag = r.CaaFlag
		inr.CaaType = r.CaaType
		inr.CaaValue = r.CaaValue
	} else if r.Rtype == "TLSA" {
		inr.TlsaUsage = r.TlsaUsage
		inr.TlsaSelector = r.TlsaSelector
		inr.TlsaMatchingType = r.TlsaMatchingType
	} else if r.Rtype == "DS" {
		inr.KeyTag = r.KeyTag
		inr.Algorithm = r.Algorithm
		inr.DigestType = r.DigestType
	} else if r.Rtype == "CERT" {
		inr.CertType = r.CertAlgorithm
		inr.CertKeyTag = r.CertKeyTag
		inr.CertAlgorithm = r.CertAlgorithm
	} else if r.Rtype == "HINFO" {
		inr.CPU = r.CPU
		inr.OS = r.OS
	} else if r.Rtype == "LOC" {
		inr.LatDeg = r.LatDeg
		inr.LatMin = r.LatMin
		inr.LatDir = r.LatDir
		inr.LongDeg = r.LongDeg
		inr.LongMin = r.LongMin
		inr.LongSec = r.LongSec
		inr.LongDir = r.LongDir
		inr.Altitude = r.Altitude
		inr.Size = r.Size
		inr.HPrecision = r.HPrecision
		inr.VPrecision = r.VPrecision
	} else if r.Rtype == "SMIMEA" {
		inr.SmimeaUsage = r.SmimeaUsage
		inr.SmimeaSelector = r.SmimeaSelector
		inr.SmimeaMatchingType = r.SmimeaMatchingType
	}

	if r.GeodnsLocation != "" {
		inr.GeodnsLocation = r.GeodnsLocation
	}
	if r.GeodnsCode != "" {
		inr.GeodnsCode = r.GeodnsCode
	}

	resp, err := inr.create()
	if err == nil {
		errmsg, isapierr := checkapierr(resp.Body())
		if isapierr {
			return r, errors.New(errmsg)
		}
		newid := gjson.GetBytes(resp.Body(), "data.id")
		r.ID = newid.String()
	}
	return r, err
}

// Read a record
func (r Record) Read(a *Apiaccess) (Record, error) {
	lsr := reclist{
		Authid:       a.Authid,
		Subauthid:    a.Subauthid,
		Authpassword: a.Authpassword,
		Domain:       r.Domain,
		Host:         r.Host,
		Rtype:        r.Rtype,
	}
	resp, err := lsr.lsrec()
	if err == nil {
		errmsg, isapierr := checkapierr(resp.Body())
		if isapierr {
			return r, errors.New(errmsg)
		}
		var ratmp map[string]retrec
		err2 := json.Unmarshal(resp.Body(), &ratmp)
		for _, rec := range ratmp {
			tmpttl, _ := strconv.Atoi(rec.TTL)
			tmppriority, _ := strconv.Atoi(rec.Priority)
			tmpframe := rec.Frame
			tmpframetitle := rec.FrameTitle
			tmpframekeywords := rec.FrameKeywords
			tmpframedescription := rec.FrameDescription
			tmpmobilemeta := rec.MobileMeta
			tmpsavepath := rec.SavePath
			tmpredirecttype := rec.RedirectType
			tmpweight, _ := strconv.Atoi(rec.Weight)
			tmpport, _ := strconv.Atoi(rec.Port)
			tmptxt := rec.Txt
			tmpmail := rec.Mail
			tmpalgorithm, _ := strconv.Atoi(rec.Algorithm)
			tmpfptype := rec.Fptype
			tmpflag := rec.Flag
			tmporder := rec.Order
			tmppref := rec.Pref
			tmpparams := rec.Params
			tmpregexp := rec.Regexp
			tmpreplace := rec.Replace
			tmpcaaflag := rec.CaaFlag
			tmpcaatype := rec.CaaType
			tmpcaavalue := rec.CaaValue
			tmptlsausage := rec.TlsaUsage
			tmptlsaselector := rec.TlsaSelector
			tmptlsamatchingtype := rec.TlsaMatchingType
			tmpkeytag := rec.KeyTag
			tmpdigesttype := rec.DigestType
			tmpcerttype := rec.CertType
			tmpcertkeytag := rec.CertKeyTag
			tmpcertalgorithm := rec.CertAlgorithm
			tmpcpu := rec.CPU
			tmpos := rec.OS
			tmplatdeg := rec.LatDeg
			tmplatmin := rec.LatMin
			tmplatsec := rec.LatSec
			tmplatdir := rec.LatDir
			tmplongdeg := rec.LongDeg
			tmplongmin := rec.LongMin
			tmplongsec := rec.LongSec
			tmplongdir := rec.LongDir
			tmpaltitude := rec.Altitude
			tmpsize := rec.Size
			tmphprecision := rec.HPrecision
			tmpvprecision := rec.VPrecision
			tmpsmimeausage := rec.SmimeaUsage
			tmpsmimeaselector := rec.SmimeaSelector
			tmpsmimeamatchingtype := rec.SmimeaMatchingType
			tmpgeodnscode := rec.GeodnsCode
			tmpgeodnslocation := rec.GeodnsLocation

			rectmp := Record{
				Domain:             r.Domain,
				ID:                 rec.ID,
				Rtype:              rec.Rtype,
				Host:               rec.Host,
				TTL:                tmpttl,
				Record:             rec.Record,
				Priority:           tmppriority,
				Frame:              tmpframe,
				FrameTitle:         tmpframetitle,
				FrameKeywords:      tmpframekeywords,
				FrameDescription:   tmpframedescription,
				MobileMeta:         tmpmobilemeta,
				SavePath:           tmpsavepath,
				RedirectType:       tmpredirecttype,
				Weight:             tmpweight,
				Port:               tmpport,
				Mail:               tmpmail,
				Txt:                tmptxt,
				Algorithm:          tmpalgorithm,
				Fptype:             tmpfptype,
				Flag:               tmpflag,
				Order:              tmporder,
				Pref:               tmppref,
				Params:             tmpparams,
				Regexp:             tmpregexp,
				Replace:            tmpreplace,
				CaaFlag:            tmpcaaflag,
				CaaType:            tmpcaatype,
				CaaValue:           tmpcaavalue,
				TlsaUsage:          tmptlsausage,
				TlsaSelector:       tmptlsaselector,
				TlsaMatchingType:   tmptlsamatchingtype,
				KeyTag:             tmpkeytag,
				DigestType:         tmpdigesttype,
				CertType:           tmpcerttype,
				CertKeyTag:         tmpcertkeytag,
				CertAlgorithm:      tmpcertalgorithm,
				CPU:                tmpcpu,
				OS:                 tmpos,
				LatDeg:             tmplatdeg,
				LatMin:             tmplatmin,
				LatSec:             tmplatsec,
				LatDir:             tmplatdir,
				LongDeg:            tmplongdeg,
				LongMin:            tmplongmin,
				LongSec:            tmplongsec,
				LongDir:            tmplongdir,
				Altitude:           tmpaltitude,
				Size:               tmpsize,
				HPrecision:         tmphprecision,
				VPrecision:         tmpvprecision,
				SmimeaUsage:        tmpsmimeausage,
				SmimeaSelector:     tmpsmimeaselector,
				SmimeaMatchingType: tmpsmimeamatchingtype,
				GeodnsLocation:     tmpgeodnslocation,
				GeodnsCode:         tmpgeodnscode,
			}
			if r.ID != "" && r.ID == rectmp.ID {
				return rectmp, err2
			}

			return rectmp, err2
		}
		return r, err2
	}
	return r, err
}

// Update a record
func (r Record) Update(a *Apiaccess) (Record, error) {
	tmpid, _ := strconv.Atoi(r.ID)
	inr := updaterec{
		Authid:       a.Authid,
		Subauthid:    a.Subauthid,
		Authpassword: a.Authpassword,
		Rid:          tmpid,
		Domain:       r.Domain,
		Host:         r.Host,
		TTL:          r.TTL,
		Record:       r.Record,
	}
	if r.Rtype == "MX" {
		inr.Priority = &r.Priority
	} else if r.Rtype == "WR" {
		inr.Frame = r.Frame
		inr.FrameTitle = r.FrameTitle
		inr.FrameKeywords = r.FrameKeywords
		inr.FrameDescription = r.FrameDescription
		inr.MobileMeta = r.MobileMeta
		inr.SavePath = r.SavePath
		inr.RedirectType = r.RedirectType
	} else if r.Rtype == "SRV" {
		inr.Priority = &r.Priority
		inr.Weight = &r.Weight
		inr.Port = &r.Port
	} else if r.Rtype == "RP" {
		inr.Txt = r.Txt
		inr.Mail = r.Mail
	} else if r.Rtype == "SSHFP" {
		inr.Algorithm = r.Algorithm
		inr.Fptype = r.Fptype
	} else if r.Rtype == "NAPTR" {
		inr.Flag = r.Flag
		inr.Order = r.Order
		inr.Pref = r.Pref
		inr.Params = r.Params
		inr.Regexp = r.Regexp
		inr.Replace = r.Replace
	} else if r.Rtype == "CAA" {
		inr.CaaFlag = r.CaaFlag
		inr.CaaType = r.CaaType
		inr.CaaValue = r.CaaValue
	} else if r.Rtype == "TLSA" {
		inr.TlsaUsage = r.TlsaUsage
		inr.TlsaSelector = r.TlsaSelector
		inr.TlsaMatchingType = r.TlsaMatchingType
	} else if r.Rtype == "DS" {
		inr.KeyTag = r.KeyTag
		inr.Algorithm = r.Algorithm
		inr.DigestType = r.DigestType
	} else if r.Rtype == "CERT" {
		inr.CertType = r.CertAlgorithm
		inr.CertKeyTag = r.CertKeyTag
		inr.CertAlgorithm = r.CertAlgorithm
	} else if r.Rtype == "HINFO" {
		inr.CPU = r.CPU
		inr.OS = r.OS
	} else if r.Rtype == "LOC" {
		inr.LatDeg = r.LatDeg
		inr.LatMin = r.LatMin
		inr.LatDir = r.LatDir
		inr.LongDeg = r.LongDeg
		inr.LongMin = r.LongMin
		inr.LongSec = r.LongSec
		inr.LongDir = r.LongDir
		inr.Altitude = r.Altitude
		inr.Size = r.Size
		inr.HPrecision = r.HPrecision
		inr.VPrecision = r.VPrecision
	} else if r.Rtype == "SMIMEA" {
		inr.SmimeaUsage = r.SmimeaUsage
		inr.SmimeaSelector = r.SmimeaSelector
		inr.SmimeaMatchingType = r.SmimeaMatchingType
	}

	if r.GeodnsLocation != "" {
		inr.GeodnsLocation = r.GeodnsLocation
	}
	if r.GeodnsCode != "" {
		inr.GeodnsCode = r.GeodnsCode
	}

	resp, err := inr.update()
	if err == nil {
		errmsg, isapierr := checkapierr(resp.Body())
		if isapierr {
			return r, errors.New(errmsg)
		}
	}
	return r, err
}

// Destroy a record
func (r Record) Destroy(a *Apiaccess) (Record, error) {
	tmpid, _ := strconv.Atoi(r.ID)
	inr := updaterec{
		Authid:       a.Authid,
		Subauthid:    a.Subauthid,
		Authpassword: a.Authpassword,
		Rid:          tmpid,
		Domain:       r.Domain,
		Host:         r.Host,
		TTL:          r.TTL,
		Record:       r.Record,
	}
	resp, err := inr.destroy()
	if err == nil {
		errmsg, isapierr := checkapierr(resp.Body())
		if isapierr {
			return r, errors.New(errmsg)
		}
	}
	return r, err
}

func (r activatefailover) Create(a *Apiaccess) (activatefailover, error) {
	log.Printf("Authid: %d, Subauthid: %d, Domain: %s, RecordId: %s", a.Authid, a.Subauthid, r.Domain, r.RecordId)

	inr := activatefailover{
		Authid:           a.Authid,
		Subauthid:        a.Subauthid,
		Authpassword:     a.Authpassword,
		Domain:           r.Domain,
		RecordId:         r.RecordId,
		FailoverType:     r.FailoverType,
		DownEventHandler: r.DownEventHandler,
		UpEventHandler:   r.UpEventHandler,
		MainIP:           r.MainIP,
		BackupIp1:        r.BackupIp1,
		BackupIp2:        r.BackupIp2,
		BackupIp3:        r.BackupIp3,
		BackupIp4:        r.BackupIp4,
		BackupIp5:        r.BackupIp5,
		MonitoringRegion: r.MonitoringRegion,
		Host:             r.Host,
		Port:             r.Port,
		Path:             r.Path,
		Content:          r.Content,
		QueryType:        r.QueryType,
		QueryResponse:    r.QueryResponse,
		CheckPeriod:      r.CheckPeriod,
		NotificationMail: r.NotificationMail,
		DeactivateRecord: r.DeactivateRecord,
		LatencyLimit:     r.LatencyLimit,
		Timeout:          r.Timeout,
		HttpRequestType:  r.HttpRequestType,
	}

	if r.FailoverType == 1 || r.FailoverType == 2 || r.FailoverType == 3 || r.FailoverType == 14 {
		// Type: PING
		inr.Timeout = r.Timeout
		inr.LatencyLimit = r.LatencyLimit
		inr.DownEventHandler = r.DownEventHandler
		inr.UpEventHandler = r.UpEventHandler
		inr.NotificationMail = r.NotificationMail
	}

	resp, err := inr.create()
	if err == nil {
		errmsg, isapierr := checkapierr(resp.Body())
		if isapierr {
			return r, errors.New(errmsg)
		}
	}
	return r, err
}
