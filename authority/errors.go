package authority

import "webtyp.com/fmt"

// ErrNoIDs: New received no id generator, so it could not create users or sessions.
var ErrNoIDs = fmt.Err("an id generator is required to create users and sessions")
