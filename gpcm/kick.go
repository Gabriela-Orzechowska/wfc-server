package gpcm

import (
	"strconv"
	"wwfc/common"
)

const (
	GetLastIGN = `SELECT last_ingamesn FROM users WHERE profile_id = $1`
)

func kickPlayer(profileID uint32, reason string) {
	playerName := ""
	announce := false
	if reason == "banned" || reason == "restricted" {
		announce = true
	}

	if session, exists := sessions[profileID]; exists {
		playerName = session.InGameName
		errorMessage := WWFCMsgKickedGeneric

		switch reason {
		case "banned":
			errorMessage = WWFCMsgProfileBannedTOSNow

		case "restricted":
			errorMessage = WWFCMsgProfileRestrictedNow

		case "restricted_join":
			errorMessage = WWFCMsgProfileRestricted

		case "moderator_kick":
			errorMessage = WWFCMsgKickedModerator

		case "room_kick":
			errorMessage = WWFCMsgKickedRoomHost

		case "invalid_elo":
			errorMessage = WWFCMsgInvalidELO

		case "too_many_frames_dropped":
			errorMessage = WWFCMsgTooManyFramesDropped

		case "network_error":
			// No error message
			common.CloseConnection(ServerName, session.ConnIndex)
			return
		}

		session.replyError(GPError{
			ErrorCode:   ErrConnectionClosed.ErrorCode,
			ErrorString: "The player was kicked from the server. Reason: " + reason,
			Fatal:       true,
			WWFCMessage: errorMessage,
		})
	}

	if !announce {
		return
	}

	if playerName == "" {
		// Get Last IGN
		err := pool.QueryRow(ctx, GetLastIGN, profileID).Scan(&playerName)
		if err != nil {
			return
		}
	}

	message := common.CreateGameSpyMessage(common.GameSpyCommand{
		Command:      "a_kick",
		CommandValue: strconv.FormatInt(int64(profileID), 10),
		OtherValues: map[string]string{
			"ban":  strconv.FormatBool(true),
			"name": playerName,
		},
	})

	for _, session := range sessions {
		common.SendPacket(ServerName, session.ConnIndex, []byte(message))
	}
}

func KickPlayer(profileID uint32, reason string) {
	mutex.Lock()
	defer mutex.Unlock()

	kickPlayer(profileID, reason)
}
