/*
* After receiver is in the snadbox,
* waits for sender to connect, receives files:
*
* - Store directory contents
* - Wait for sender to connect
* - Receive files, add to stored directory contents (no duplicates)
*/


package snadbox

import (
	"fmt"
	"net"
	"bufio"
	"strings"
	"time"
)

