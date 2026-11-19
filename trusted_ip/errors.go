package trustedip

import "webtyp.com/fmt"

// msgThisMode names the mode at the start of its errors.
const msgThisMode = "sign-in by trusted device"

// Errors of this mode.
var (
	ErrNoDevices        = fmt.Err(msgThisMode, "needs the module that registers the devices")
	ErrNotDevices       = fmt.Err("the devices module does not say which device each person may use")
	ErrPortsIncomplete  = fmt.Err(msgThisMode, "was built without the administrator pieces")
	ErrAdminsUnreadable = fmt.Err("the administrators could not be read")
)
