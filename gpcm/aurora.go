package gpcm

import (
	"strconv"
	"wwfc/common"
	"wwfc/qr2"
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
