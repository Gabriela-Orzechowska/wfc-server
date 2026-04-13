package api

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"wwfc/common"

	"github.com/jackc/pgx/v4"
)


const (
	SearchUserBan           = `SELECT has_ban, ban_tos, ng_device_id FROM users WHERE has_ban = true AND (profile_id = $1 OR last_ip_address = $2) AND (ban_expires IS NULL OR ban_expires > $3) ORDER BY ban_tos DESC LIMIT 1`
    CurrentRevision         = 5
)

// Dev keys for verification version not used in either v0.1 or in next release
// Should delete this logic completely
var (
    AESKey = []byte{0x74, 0xF2, 0xCC, 0xA9, 0x13, 0xEB, 0xC2, 0x88, 0x54, 0xB0, 0x1D, 0x88, 0xE8, 0x5D, 0x37, 0x40, 0x49, 0x9A, 0x32, 0xAD, 0x89, 0xD1, 0xD6, 0xAF, 0x7B, 0x21, 0x21, 0x83, 0x61, 0xA2, 0xF0, 0x4B}
    HMACKey = []byte{0x53, 0x17, 0x10, 0xf8, 0xe6, 0x00, 0x1a, 0x2f, 0x6b, 0x97, 0x81, 0x61, 0x22, 0xa5, 0xfa, 0x6c, 0x87, 0xc5, 0xaf, 0x14, 0x5f, 0x9b, 0xa9, 0xf9, 0xd5, 0xd2, 0x6a, 0xa7, 0x84, 0xb2, 0x0e, 0x3a}
)

func ReadUserIP(r *http.Request) string {
    IPAddress := r.Header.Get("X-Real-Ip")
    if IPAddress == "" {
        IPAddress = r.Header.Get("X-Forwarded-For")
    }
    if IPAddress == "" {
        IPAddress = r.RemoteAddr
    }
    return IPAddress
}

func EncodeToken(ip net.IP) ([]byte, error) {
    ip4 := ip.To4()
    if ip4 == nil {
        return nil, errors.New("only IPv4 supported")
    }
    buf := new(bytes.Buffer)
    buf.Write(ip4)

    ts := uint32(time.Now().Unix() / 3600)
    binary.Write(buf, binary.BigEndian, ts)

    nonce := make([]byte, 8)
    _, err := rand.Read(nonce)
    if err != nil {
        return nil, err
    }

    buf.Write(nonce)

    payload := buf.Bytes() // 16

    block, err := aes.NewCipher(AESKey)
    if err != nil {
        return nil, err
    }

    aesNonce := make([]byte, 12)
    _, err = rand.Read(aesNonce)
    if err != nil {
        return nil, err
    }
    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    ciphertext := aesgcm.Seal(nil, aesNonce, payload, nil)
    blob := append(aesNonce, ciphertext...)

    mac := hmac.New(sha256.New, HMACKey)
    mac.Write(blob)
    signature := mac.Sum(nil)

    token := append(blob, signature...)
    return token, nil
}

func DecodeToken(token []byte) (net.IP, bool, error) {
    if len(token) < 12+16+32 {
        return nil, false, errors.New("token invalid")
    }

    blob := token[:len(token)-32]
    sig := token[len(token)-32:]

    mac := hmac.New(sha256.New, HMACKey)
    mac.Write(blob)
    expected := mac.Sum(nil)
    if !hmac.Equal(sig, expected) {
        return nil, false, errors.New("invalid signature")
    }

    aesNonce := blob[:12]
    ciphertext := blob[12:]
    block, err := aes.NewCipher(AESKey)
    if err != nil{
        return nil, false, err
    }
    aesgcm, err := cipher.NewGCM(block)
    if err != nil{
        return nil, false, err
    }

    payload, err := aesgcm.Open(nil, aesNonce, ciphertext, nil)
    if err != nil{
        return nil, false, err
    }

    if len(payload) != 16 {
        return nil, false, errors.New("invalid payload")
    }

    ip := net.IP(payload[:4])
    ts := uint32(binary.BigEndian.Uint32(payload[4:8]))

    return ip, (ts + 25 ) > (uint32(time.Now().Unix() / 3600)) , nil

}

func HandleVerify(w http.ResponseWriter, r *http.Request) {
	data, ok := handleVerifyImpl(w, r)
	if !ok {
        var jsonData = "Bad Request"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
		w.Write([]byte(jsonData))
	} else {
		w.Header().Set("Content-Type", "binary")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
	}
}

func HandleVerifyV3(w http.ResponseWriter, r *http.Request) {
	data, ok := handleVerifyImplV3(w, r)
	if !ok {
        var jsonData = "Bad Request"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
		w.Write([]byte(jsonData))
	} else {
		w.Header().Set("Content-Type", "binary")
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

func handleVerifyImplV3(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
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

    var new_token []byte = make([]byte, 76)
    var user_ip uint32 = 0
    if userType == 0 {
        ip_string := ReadUserIP(r)
        ip, _, err := net.SplitHostPort(ip_string)
        

        if err == nil {
            new_token, err = EncodeToken(net.ParseIP(ip))
            if err != nil {
                fmt.Println("encoding error: ", err)
            }
        }
        user_ip = binary.BigEndian.Uint32(net.ParseIP(ip).To4()) ^ 0xBCA3F166;
        user_ip = user_ip * 0x9E3779B1;
        user_ip = user_ip & 0xFFFFFFFF;
    }

    var ret = struct {
        header uint32
        revision uint32
        user_type uint32
        user_id uint32
        token_string [76]byte
        version_string [20]byte
    }{0x43535644, CurrentRevision, userType, user_ip, [76]byte(new_token), [20]byte{0x00, 0x76, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x32}}

    buf := &bytes.Buffer{}

    err = binary.Write(buf, binary.BigEndian, ret)
    return buf.Bytes(), true
}
