/*
* Contains logic for establishing a connection
* and sending data to the receiver using TCP:
*
* - Connect to a receiver's ip over the network
* - Accepts multiple arguments, multiple calls for files to send
* - Only access directory where snad is opened
* - Store directories of sent files so same file cannot be sent twice
* - Distribute threads amongst files
*/

package snadbox

import (
	"fmt"
	"network"
	"strings"
	"time"
)



