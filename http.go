package goup

import "fmt"

type httpReply struct {
	Code int    `json:"code"`
	Data any    `json:"data"`
	Mesg string `json:"mesg"`
}

func (hr httpReply) Error() string {
	return fmt.Sprintf("%d %s", hr.Code, hr.Mesg)
}
