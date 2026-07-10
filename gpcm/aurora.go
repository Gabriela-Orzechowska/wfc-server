package gpcm

import (
	"errors"
	"fmt"
	"strconv"
	"time"
	"wwfc/common"
	"wwfc/logging"
	"wwfc/qr2"

	"github.com/jackc/pgx/v4"
)

type OnlineGameData struct {
	Gamedata  []byte
	Name      string
	StartTime time.Time
	EndTime   time.Time
	Id        int
	IsActive  bool
}

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

const (
	GetGamemode = `
		SELECT *, $1 >= start_time AND $1 < end_time AS is_active
		FROM gamemodes WHERE $1 < end_time
		ORDER BY NOT ($1 >= start_time AND $1 < end_time), start_time ASC LIMIT 1;
	`
	CheckInterval       = time.Duration(30) * time.Second
	GamemodeDataVersion = 1
)

var (
	lastGamemodeData  OnlineGameData
	lastGamemodeCheck time.Time
	hasGamemodeData   bool
)

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
			if errors.Is(err, pgx.ErrNoRows) {
				hasGamemodeData = false
			} else {
				logging.Error("AUR", "Failed to get gamemode data:", err)
				return
			}
		} else {
			hasGamemodeData = true
		}
	}

	if !hasGamemodeData {
		message := common.CreateGameSpyMessage(common.GameSpyCommand{
			Command:      "a_gm",
			CommandValue: "none",
		})

		g.WriteBuffer += message
		return
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
			"active":  strconv.FormatInt(int64(isactive), 10),
			"name":    lastGamemodeData.Name,
			"region":  strconv.FormatInt(int64(lastGamemodeData.Id+4000), 10),
			"min":     strconv.FormatInt(int64(minutes+1), 10),
			"version": strconv.FormatInt(int64(GamemodeDataVersion), 10),
		},
	})

	g.WriteBuffer += message
}

// For webhook
var (
	reasonNameMap = map[string]string{
		"bad_packet":   "Bad Packet",
		"lap_trolling": "Lap Trolling",
	}

	lastReportTime = map[string]map[string]time.Time{}
)

const (
	ReportInterval = time.Second * 10
)

func (g *GameSpySession) handleAuroraReport(command common.GameSpyCommand) {
	reason := command.CommandValue
	name, ok := reasonNameMap[reason]
	if !ok {
		logging.Error(ServerName, "Invalid report command, invalid reason. Got", reason)
		return

	}

	playerIdS, ok := command.OtherValues["player_id"]
	if !ok {
		logging.Error(ServerName, "Invalid report command, missing player_id")
		return
	}
	playerId, err := strconv.Atoi(playerIdS)
	if err != nil {
		logging.Error(ServerName, "Invalid report command, invalid player_id. Got", playerIdS)
		return
	}

	playerFC := common.CalcFriendCodeString(uint32(playerId), g.User.GsbrCode[:4])
	reporterFC := common.CalcFriendCodeString(uint32(g.User.ProfileId), g.User.GsbrCode[:4])

	_, ok = lastReportTime[playerFC]
	if !ok {
		lastReportTime[playerFC] = make(map[string]time.Time)
	}

	if time.Now().Sub(lastReportTime[playerFC][reason]) < ReportInterval {
		return
	}
	lastReportTime[playerFC][reason] = time.Now()

	content := fmt.Sprintf("**Reason**: %s\n**Reported User**: %s\n**Reported By**: %s",
		name, playerFC, reporterFC,
	)
	common.SendWebhookSimple("Player Report", content)
}
