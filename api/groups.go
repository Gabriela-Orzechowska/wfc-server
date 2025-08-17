package api

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"wwfc/qr2"
)

func HandleGroups(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.String())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	groups := qr2.GetGroups(query["game"], query["id"], true)

	var jsonData []byte
	if len(groups) == 0 {
		jsonData, _ = json.Marshal([]string{})
	} else {
		jsonData, err = json.Marshal(groups)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
	w.Write(jsonData)
}

func HandlePlayerCount(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.String())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	groups := qr2.GetGroups(query["game"], query["id"], true)


    var players int = 0

	if len(groups) == 0 {
		players = 0
	} else {
		for _, group := range groups {
			if group.MatchType == "private" {
				continue
			}
			players += len(group.Players)
		}
	}


	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Length", "4")
    bs := make([]byte, 4)
    binary.BigEndian.PutUint32(bs, uint32(players));
    w.Write(bs);

}
