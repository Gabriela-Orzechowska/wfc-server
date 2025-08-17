package api

import (
    "bytes"
    "net"
	"net/http"
	"net/url"
    "time"
    "encoding/binary"
    "wwfc/common"
    "strconv"
	"github.com/jackc/pgx/v4"
    "crypto/sha1"
)

const (
	SearchUserBan           = `SELECT has_ban, ban_tos, ng_device_id FROM users WHERE has_ban = true AND (profile_id = $1 OR last_ip_address = $2) AND (ban_expires IS NULL OR ban_expires > $3) ORDER BY ban_tos DESC LIMIT 1`
    CurrentRevision         = 5
)

func HandleVerify(w http.ResponseWriter, r *http.Request) {
	data, ok := handleVerifyImpl(w, r)
	if !ok {
        var jsonData = "Bad Request"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
		w.Write([]byte(jsonData))
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
	}
}

func handleVerifyImpl(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	u, err := url.Parse(r.URL.String())
	if err != nil {
		return []byte{}, false
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return []byte{}, false
	}

    data, exists := query["data"]
	if !exists {
		return []byte{}, false
	}

	dataBytes, err := common.Base64DwcEncoding.DecodeString(data[0])
    if err != nil {
		return []byte{}, false
    }

    sign := binary.BigEndian.Uint32(dataBytes[0x000:0x004])
    if sign != 0x41525344 {
		return []byte{}, false
    }


    pid := binary.BigEndian.Uint32(dataBytes[0x008:0x00C])
    var profileId int = int(pid)

	var banExists bool
	var banTOS bool
	var bannedDeviceId uint32
	timeNow := time.Now()
    ipAddress, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
		return []byte(ipAddress), false 
    }

    var userType uint32 = 0

	err = pool.QueryRow(ctx, SearchUserBan, profileId, ipAddress, timeNow).Scan(&banExists, &banTOS, &bannedDeviceId)
	if err != nil {
		if err != pgx.ErrNoRows {
            userType = 1
		}

		banExists = false
	}

    if banExists {
        userType = 1
    }

    var token uint64 = 0
    if userType == 0 {
        deviceId := binary.BigEndian.Uint32(dataBytes[0x01A:0x20])

        bs := make([]byte, 4)

        binary.BigEndian.PutUint32(bs, deviceId)

        hasher := sha1.New()
        hasher.Write(bs)

        token = binary.BigEndian.Uint64(hasher.Sum(nil)[0x000:0x008])
    }

    var ret = struct {
        header uint32
        revision uint32
        user_type uint32
        val uint32
        token_id uint64
        version_string [20]byte
    }{0x43535644, CurrentRevision, userType, 0, token, [20]byte{0x00, 0x76, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x32}}

    buf := &bytes.Buffer{}

    err = binary.Write(buf, binary.BigEndian, ret)
    return buf.Bytes(), true
}
