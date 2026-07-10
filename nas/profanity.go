package nas

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"
	"wwfc/common"
	"wwfc/logging"

	"golang.org/x/text/unicode/norm"
)

var profanityFilePath = "./profanity.txt"
var profanityFileLines []string = nil
var lastModTime time.Time

var symbolMapping = map[rune]rune{
	'1': 'i',
	'0': 'o',
	'5': 's',
	'4': 'a',
	'3': 'e',
	'7': 't',
	'9': 'g',
	'2': 'z',
	'(': 'c',
}

var mkwiiMapping = map[rune]rune{
	// Funny numbers
	'\u2460': '0',
	'\u2461': '1',
	'\u2462': '2',
	'\u2463': '3',
	'\u2464': '4',
	'\u2465': '5',
	'\u2466': '6',
	'\u2467': '7',
	'\u2468': '8',
	'\u2469': '9',

	// DS symbols
	'\uE000': 'a',
	'\uE001': 'b',
	'\uE002': 'x',
	'\uE003': 'y',
	'\uE004': 'l',
	'\uE005': 'r',

	// Controllers
	'\uF030': '2',
	'\uF031': '2',
	'\uF034': 'a',
	'\uF035': 'a',
	'\uF038': 'a',
	'\uF039': 'a',
	'\uF03C': 'a',
	'\uF03D': 'a',
	'\uF041': 'b',
	'\uF043': '1',
	'\uF050': 'b',
	'\uF058': 'b',
	'\uF05E': 's',
	'\uF05F': 's',

	// Ranks
	'\uF078': 'a',
	'\uF079': 'b',
	'\uF07A': 'c',
	'\uF07B': 'd',
	'\uF07C': 'e',
}

func CacheProfanityFile() error {
	fileInfo, err := os.Stat(profanityFilePath)
	if err != nil {
		return err
	}

	if !fileInfo.ModTime().After(lastModTime) && profanityFileLines != nil {
		return nil
	}

	file, err := os.Open(profanityFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	profanityFileLines = nil
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			continue
		}

		profanityFileLines = append(profanityFileLines, line)
	}

	if profanityFileLines == nil {
		return errors.New("the file '" + profanityFilePath + "' is empty")
	}

	lastModTime = fileInfo.ModTime()
	return nil
}

func normalizeWord(word string) string {
	word = strings.ToLower(word)
	word = norm.NFKD.String(word)

	var result strings.Builder
	for _, r := range word {
		if unicode.Is(unicode.Mn, r) {
			continue
		}

		if replacement, ok := mkwiiMapping[r]; ok {
			r = replacement
		}

		if replacement, ok := symbolMapping[r]; ok {
			result.WriteRune(replacement)
		} else if unicode.IsLetter(r) || unicode.IsDigit(r) {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func IsBadWord(word string) (bool, error) {
	if !isProfanityFileCached() {
		err := CacheProfanityFile()
		if err != nil {
			return false, errors.New("the file '" + profanityFilePath + "' has not been cached")
		}

	}

	normalizedWord := normalizeWord(word)
	for _, line := range profanityFileLines {
		if strings.EqualFold(line, normalizedWord) {
			return true, nil
		}
	}

	return false, nil
}

func checkUsernameFlag(username string) {
	normalized := normalizeWord(username)
	for _, line := range profanityFileLines {
		if strings.Contains(normalized, line) {
			common.SendWebhookSimple("Username Report",
				fmt.Sprintf("Name: %s\nFlag: %s", username, line))
			return
		}
	}
}

func CheckUsernameProfanity(username string) (bool, error) {
	if !isProfanityFileCached() {
		err := CacheProfanityFile()
		if err != nil {
			return false, errors.New("the file '" + profanityFilePath + "' has not been cached")
		}

	}
	normalized := normalizeWord(username)
	logging.Info("NAS", "Checking name:", username, "->", normalized)
	for _, line := range profanityFileLines {
		if strings.EqualFold(normalized, line) {
			return true, nil
		}
		if strings.HasPrefix(normalized, line) {
			return true, nil
		}
		if strings.HasSuffix(normalized, line) {
			return true, nil
		}
	}
	checkUsernameFlag(username)
	return false, nil
}

func isProfanityFileCached() bool {
	fileInfo, err := os.Stat(profanityFilePath)
	if err != nil {
		return false
	}
	return profanityFileLines != nil && !fileInfo.ModTime().After(lastModTime)
}
