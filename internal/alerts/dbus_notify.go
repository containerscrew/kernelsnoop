package alerts

import "github.com/gen2brain/beeep"

// func SendNotification(iconPath, title, text string) error {

// 	if iconPath == "" {
// 		iconPath = "dialog-information" // Set the default icon
// 	}

// 	cmd := exec.Command("notify-send", "-i", iconPath, title, text)
// 	err := cmd.Run()

// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }

func SendNotification(title, message, iconPath string) error {
	err := beeep.Alert(title, message, iconPath)
	if err != nil {
		return err
	}
	return nil
}
