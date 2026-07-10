package common

import "github.com/gtuk/discordwebhook"

var (
	username = "Cosmos WFC Reports"
)

func SendWebhookSimple(title string, description string) error {
	embed := discordwebhook.Embed{
		Title:       &title,
		Description: &description,
	}

	dmessage := discordwebhook.Message{
		Username: &username,
		Embeds:   &[]discordwebhook.Embed{embed},
	}

	err := discordwebhook.SendMessage(GetConfig().ReportWebhook, dmessage)
	return err
}