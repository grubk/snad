/*
* Contains logic for:
*
* - Opening UDP connections (join snadbox with ip and nickname)
* - Forming direct TCP connections between sender and receiver
* - Storing { nickname : ip } snadbox map
* - Closing TCP connections (can be done by either sender or receiver)
* - Closing UDP connections (remove device from snadbox)
*/

package snadbox
