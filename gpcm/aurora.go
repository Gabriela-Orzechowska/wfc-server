package gpcm

import (
	"strconv"
	"time"
	"wwfc/common"
	"wwfc/logging"
	"wwfc/qr2"
)

type OnlineGameData struct {
	Gamedata  []byte
	Name      string
	StartTime time.Time
	EndTime   time.Time
	Id        int
	IsActive  bool
}

const (
	GetGamemode = `
		SELECT *, $1 >= start_time AND $1 < end_time AS is_active
		FROM gamemodes WHERE $1 < end_time
		ORDER BY NOT ($1 >= start_time AND $1 < end_time), start_time ASC LIMIT 1;
	`
	CheckInterval = time.Duration(1) * time.Minute
)

var (
	lastGamemodeData  OnlineGameData
	lastGamemodeCheck time.Time
)

func (g *GameSpySession) handlePlayerCount(command common.GameSpyCommand) {
	groups := qr2.GetGroups([]string{}, []string{}, false)
	players := 0

	for _, group := range groups {
		if group.MatchType == "private" {
			continue
		}
		players += len(group.Players)
	}

	message := common.CreateGameSpyMessage(common.GameSpyCommand{
		Command:      "a_pc",
		CommandValue: strconv.FormatInt(int64(players), 10),
	})
	g.WriteBuffer += message
}

func (g *GameSpySession) handleGetGamemode(command common.GameSpyCommand) {
	timeNow := time.Now().UTC()

	if lastGamemodeCheck.IsZero() || timeNow.Compare(lastGamemodeCheck.Add(CheckInterval)) > 0 {
		lastGamemodeCheck = timeNow
		err := pool.QueryRow(ctx, GetGamemode, timeNow).Scan(
			&lastGamemodeData.Id,
			&lastGamemodeData.Gamedata,
			&lastGamemodeData.Name,
			&lastGamemodeData.StartTime,
			&lastGamemodeData.EndTime,
			&lastGamemodeData.IsActive)

		if err != nil {
			logging.Error("AUR", "Failed to get gamemode data:", err)
			return
		}
	}

	var (
		isactive int
		minutes  int
	)

	if lastGamemodeData.IsActive {
		isactive = 1
		diff := lastGamemodeData.EndTime.Sub(time.Now())
		minutes = int(diff.Minutes())
	} else {
		isactive = 0
		diff := lastGamemodeData.StartTime.Sub(time.Now())
		minutes = int(diff.Minutes())
	}

	message := common.CreateGameSpyMessage(common.GameSpyCommand{
		Command:      "a_gm",
		CommandValue: common.Base64DwcEncoding.EncodeToString(lastGamemodeData.Gamedata),
		OtherValues: map[string]string{
			"active": strconv.FormatInt(int64(isactive), 10),
			"name":   lastGamemodeData.Name,
			"region": strconv.FormatInt(int64(lastGamemodeData.Id+4000), 10),
			"min":    strconv.FormatInt(int64(minutes), 10),
		},
	})

	g.WriteBuffer += message
}
