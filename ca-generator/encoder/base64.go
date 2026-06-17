package encoder

import (
	"encoding/base64"
)

func EncodeBase64(
	content []byte,
) string {

	return base64.
		StdEncoding.
		EncodeToString(
			content,
		)
}
