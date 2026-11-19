package passkey

import "webtyp.com/fmt"

// msgSetupCode is the log line that carries the one-time setup code.
const msgSetupCode = "no administrator yet: open the app and enter this one-time code to create one"

// exampleOrigin shows the shape of an origin; it is data in the message, never a dictionary key.
var exampleOrigin = "https://app.example.com"

// Errors of this mode.
var (
	ErrAdminsUnreadable = fmt.Err("the administrators could not be read")
	ErrOriginRequired   = fmt.Err("passkey: the address of the app is required, for example", exampleOrigin)
)
