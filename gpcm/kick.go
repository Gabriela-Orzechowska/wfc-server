package gpcm

import (
	"strconv"
	"wwfc/common"
)

func kickPlayer(profileID uint32, reason string) {
	playerName := ""
	announce := false
	isBan := false

	if session, exists := sessions[profileID]; exists {
		playerName = session.InGameName
		errorMessage := WWFCMsgKickedGeneric

		switch reason {
		case "banned":
			errorMessage = WWFCMsgProfileBannedTOSNow
			announce = true
			isBan = true

		case "restricted":
			errorMessage = WWFCMsgProfileRestrictedNow
			announce = true
			isBan = true

		case "restricted_join":
			errorMessage = WWFCMsgProfileRestricted

		case "moderator_kick":
			errorMessage = WWFCMsgKickedModerator
			announce = true
			isBan = true

		case "room_kick":
			errorMessage = WWFCMsgKickedRoomHost
			announce = true

		case "invalid_elo":
			errorMessage = WWFCMsgInvalidELO

		case "too_many_frames_dropped":
			errorMessage = WWFCMsgTooManyFramesDropped
			announce = true

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

	message := common.CreateGameSpyMessage(common.GameSpyCommand{
		Command:      "a_kick",
		CommandValue: strconv.FormatInt(int64(profileID), 10),
		OtherValues: map[string]string{
			"ban":  strconv.FormatBool(isBan),
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
