package goup

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

type (
	TracedError interface {
		Err() error
		Error() string
		Stack() []string
		Describe(string, ...any)
		Trace()
	}
	exception struct {
		err   error
		msg   string
		trace []string
	}
)

func assert(e interface{}, ntfy ...interface{}) {
	var err TracedError
	switch e.(type) {
	case nil:
	case bool:
		if !e.(bool) {
			mesg := "assertion failed"
			if len(ntfy) > 0 {
				mesg = ntfy[0].(string)
				if len(ntfy) > 1 {
					mesg = fmt.Sprintf(mesg, ntfy[1:]...)
				}
			}
			err = &exception{err: errors.New(mesg)}
		}
	case TracedError:
		err = e.(TracedError)
	case error:
		err = &exception{err: e.(error)}
	default:
		err = &exception{err: fmt.Errorf("assert: expect error or bool, got %T", e)}
	}
	if err != nil {
		err.Trace()
		panic(err)
	}
}

func (ex *exception) Trace() {
	if len(ex.trace) > 0 {
		return
	}
	n := 1
	for {
		n++
		pc, file, line, ok := runtime.Caller(n)
		if !ok {
			break
		}
		f := runtime.FuncForPC(pc)
		name := f.Name()
		if strings.HasPrefix(name, "runtime.") {
			continue
		}
		fn := strings.Split(file, "/")
		if len(fn) > 1 {
			file = strings.Join(fn[len(fn)-2:], "/")
		}
		ex.trace = append(ex.trace, fmt.Sprintf("(%s:%d) %s", file, line, name))
	}
}

func (ex *exception) Describe(msg string, args ...interface{}) {
	ex.msg = fmt.Sprintf(msg, args...)
}

func (ex exception) Err() error {
	return ex.err
}

func (ex exception) Error() string {
	msg := ex.msg
	if msg == "" {
		msg = ex.Err().Error()
	}
	stack := []string{msg}
	for _, t := range ex.trace {
		stack = append(stack, "\t"+t)
	}
	return strings.Join(stack, "\n")
}

func (ex exception) Stack() []string {
	return ex.trace
}

func trace(e interface{}) TracedError {
	var ex exception
	switch err := e.(type) {
	case TracedError:
		return err
	case error:
		ex.err = err
	default:
		ex.err = fmt.Errorf("%v", e)
	}
	ex.Trace()
	return &ex
}
