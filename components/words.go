package components

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var adjectives = []string{
	"silly", "clever", "brave", "quiet", "eager", "jolly", "sneaky", "plucky",
	"grumpy", "sunny", "witty", "zippy", "cozy", "spry", "dizzy", "bouncy",
	"cheeky", "gentle", "sly", "bold", "swift", "fuzzy", "wobbly", "nimble",
	"crafty", "loyal", "curious", "daring", "gleeful", "grouchy", "handy",
	"hasty", "hazy", "jumpy", "keen", "lucky", "mellow", "merry", "mighty",
	"nifty", "peppy", "perky", "plain", "proud", "rowdy", "rusty", "scrappy",
	"shy", "sleepy", "smug", "snappy", "snug", "sparky", "spunky", "spry",
	"stealthy", "stormy", "stubborn", "sturdy", "sunny", "tidy", "tiny",
	"tricky", "trusty", "vivid", "wacky", "wild", "wily", "wise", "wry",
	"zany", "breezy", "bubbly", "chatty", "chipper", "chunky", "dapper",
	"dashing", "dreamy", "feisty", "fickle", "flashy", "fluffy", "frisky",
	"frosty", "gallant", "giddy", "glossy", "goofy", "gritty", "husky",
}

var toys = []string{
	"robot", "kite", "yo-yo", "top", "drone", "blocks", "puzzle", "kazoo",
	"marble", "slinky", "rocket", "puppet", "domino", "unicycle", "scooter",
	"whistle", "balloon", "frisbee", "jigsaw", "abacus", "spinner", "trumpet",
	"glider", "compass", "lantern", "paddle", "pinwheel", "rattle", "seesaw",
	"skateboard", "sled", "snowglobe", "tambourine", "teddy", "trampoline",
	"unicorn", "wagon", "xylophone", "dice", "checkers", "chess", "harmonica",
	"jacks", "kaleidoscope", "lego", "marionette", "maracas", "origami",
	"parachute", "periscope", "pogo", "sailboat", "satellite", "slingshot",
	"submarine", "surfboard", "telescope", "tricycle", "trombone", "ukulele",
	"viewfinder", "windmill", "zeppelin", "blimp", "boomerang", "bugle",
	"bulldozer", "buoy", "catapult", "clockwork", "cymbal", "flute", "gizmo",
	"gyroscope", "helicopter", "hovercraft", "joystick", "kalimba", "lasso",
	"magnet", "megaphone", "monorail", "otter", "paperclip", "tugboat",
	"pinball", "pretzel", "raccoon", "sparkler", "spyglass", "walkie-talkie",
}

func randomWord(words []string) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
	if err != nil {
		return "", fmt.Errorf("select random word: %w", err)
	}
	return words[n.Int64()], nil
}

// GenerateName picks a random adjective-toy pair, retrying until it finds
// one not already present in taken, guaranteeing uniqueness within a pool.
func GenerateName(taken Set[string]) (string, error) {
	for {
		adj, err := randomWord(adjectives)
		if err != nil {
			return "", err
		}
		toy, err := randomWord(toys)
		if err != nil {
			return "", err
		}
		name := fmt.Sprintf("%s-%s", adj, toy)
		if taken == nil || !taken.Contains(name) {
			return name, nil
		}
	}
}
