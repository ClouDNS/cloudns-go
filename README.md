# ClouDNS-Go

This is an API-Client for the [ClouDNS HTTP API](https://www.cloudns.net/wiki/article/42/) written in [Go](https://golang.org)

## Usage

### Structs

There are three structs that you need to know:

 * **Apiaccess**: Holds your authentication parameters (auth-id/sub-auth-id, auth-password)
 * **Atention**: If you are using API auth sub user(sub-auth-id), you need first to delegate the DNS zone that you want to make changes. If you don't have an access you will receive the "Missing domain name" error.
```go
// Apiaccess ClouDNS API Credentials, see https://www.cloudns.net/wiki/article/42/
type Apiaccess struct {
	Authid       int    `json:"auth-id,omitempty"`
	Subauthid    int    `json:"sub-auth-id,omitempty"`
	Authpassword string `json:"auth-password"`
}
```

 * **Zone**: Holds information about a zone
```go
// Zone is the external representation of a zone
// check the ...zone types in api.go for details
type Zone struct {
	Domain string   `json:"domain-name"`
	Ztype  string   `json:"zone-type"`
	Ns     []string `json:"ns,omitempty"`
}
```
 * **Record**: Holds information about a record
 ```go
 // Record is the external representation of a record
// check the ...record types in api.go for details
type Record struct {
	ID     string `json:"id"`
	Domain string `json:"domain-name"`
	Host   string `json:"host"`
	Rtype  string `json:"record-type"`
	TTL    int    `json:"ttl"`
	Record string `json:"record"`
}
```
 

### Examples for the structs

```go
a := cloudns.Apiaccess{
    Authid:       1234,
    Authpassword: "super-secret-password",
}

z := cloudns.Zone{
    Domain: "testdomain.xxx",
    Ztype:  "master",
}

r := cloudns.Record{
    Domain: "testdomain.xxx",
    ID:     "",
    Host:   "foo",
    Rtype:  "TXT",
    Record: "bar",
    TTL:    3600,
}
 ```

### Methods
 
These structs have methods, that call the API, most of them return either an Array of the other ones or the updated input struct and an error.


**Create(*auth)**: create a zone

```go
fmt.Println("create zone testdomain.xxx")
zc, zcerr := z.Create(&a)
if zcerr == nil {
    spew.Println(zc)
z = zc
} else {
    spew.Println(zcerr)
}
```

**Destroy(*auth)**: destroy a zone

```go
fmt.Println("destroying zone testdomain.xxx ...")
zd, zderr := z.Destroy(&a)
if zderr == nil {
    spew.Println(zd)
} else {
    spew.Println(zderr)
}
```

#### Record Methods

**Create(*auth)**: Create a record
```go
fmt.Println("creating record foo TXT bar 3600")
rc, rcerr := r.Create(&a)
if rcerr == nil {
    spew.Println(rc)
} else {
    spew.Println(rcerr)
}
```

**Update(*auth)**: Update a record
```go
rc.Record = "foobar"
fmt.Println("Updating record to foo TXT foobar 3600")
ru, ruerr := rc.Update(&a)
if ruerr == nil {
    spew.Println(ru)
} else {
    spew.Println(ruerr)
}
```

**Read(*auth)**: Read a record
```go
fmt.Println("Reading Record back")
rr, rrerr := ru.Read(&a)
if rrerr == nil {
    spew.Println(rr)
} else {
    spew.Println(rrerr)
}
```

**Destroy(*auth)**: Destroy a record
```go
fmt.Println("Destroying record")
rd, rderr := rr.Destroy(&a)
if rderr == nil {
    spew.Println(rd)
} else {
    spew.Println(rderr)
}
```