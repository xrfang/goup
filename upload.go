package goup

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type (
	Config struct {
		CORS  bool   //cross-origin resource sharing
		Limit int64  //max upload size in byte
		Queue string //temp dir for chunks
		Store string //final file directory
	}
	Logger     func(string, ...any)
	Auth       func(string, *http.Request) error
	uploadArgs struct {
		files any      //file data
		names []string //file name
		cnt   int      //number of chunks
		idx   int      //current chunk index (starting from 1)
		size  int      //size of current chunk (optional)
		md5   string   //MD5 checksum of current chunk (optional)
		token string   //access token (optional)
	}
	uploadHandler struct {
		cfg  *Config
		log  func(string, ...any)
		auth func(string, *http.Request) error //authenticator
	}
)

func NewHandler(cfg *Config, log Logger, auth Auth) *uploadHandler {
	var uh uploadHandler
	uh.cfg = cfg
	uh.log = log
	if uh.log == nil {
		uh.log = func(msg string, args ...any) {
			if !strings.HasSuffix(msg, "\n") {
				msg += "\n"
			}
			fmt.Printf(msg, args...)
		}
	}
	uh.auth = auth
	return &uh
}

func emit(code int, data any, mesg string) {
	panic(httpReply{Code: code, Data: data, Mesg: mesg})
}

func getUploadArgs(r *http.Request) *uploadArgs {
	var a uploadArgs
	q := make(url.Values)
	getInt := func(name string, def int) int {
		if q.Has(name) {
			v, err := strconv.Atoi(q.Get(name))
			if err != nil {
				emit(http.StatusBadRequest, map[string]any{
					"key": name,
					"val": q.Get(name),
					"err": err.Error(),
				}, "not a valid integer")
			}
			return v
		}
		return def
	}
	for _, c := range r.Cookies() {
		q.Add(c.Name, c.Value)
	}
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		emit(400, nil, err.Error())
	}
	switch ct {
	case "application/octet-stream":
		for k, vs := range r.URL.Query() {
			q[k] = vs
		}
		a.files = r.Body
		name := q.Get("name")
		if name == "" {
			emit(http.StatusBadRequest, nil, "missing 'name'")
		}
		a.names = []string{name}
		for k, vs := range r.URL.Query() {
			q[k] = vs
		}
	case "multipart/form-data":
		assert(r.ParseMultipartForm(1024 * 1024))
		for k, vs := range r.MultipartForm.Value {
			q[k] = vs
		}
		for k, vs := range r.URL.Query() {
			q[k] = vs
		}
		rx := regexp.MustCompile(`^file\d*$`)
		var fhs []*multipart.FileHeader
		for fn, fh := range r.MultipartForm.File {
			if rx.MatchString(fn) {
				if len(fh) != 1 {
					emit(http.StatusBadRequest, nil, "invalid multipart form (file header count not 1)")
				}
				nn := strings.Replace(fn, "file", "name", 1)
				name := q.Get(nn)
				if name == "" {
					a.names = append(a.names, fh[0].Filename)
				} else {
					a.names = append(a.names, name)
				}
				fhs = append(fhs, fh[0])
			}
		}
		if len(fhs) == 0 {
			emit(http.StatusBadRequest, nil, "invalid multipart form (no matching file component)")
		}
		a.files = fhs
		for k, vs := range r.URL.Query() {
			q[k] = vs
		}
	default: //按照application/x-www-form-urlencoded解读
		assert(r.ParseForm())
		for k, vs := range r.PostForm {
			q[k] = vs
		}
		for k, vs := range r.URL.Query() {
			q[k] = vs
		}
		name := q.Get("name")
		if name == "" {
			emit(http.StatusBadRequest, nil, "missing 'name'")
		}
		a.names = []string{name}
		if q.Has("file") {
			a.files = q.Get("file")
		}
	}
	a.cnt = getInt("cnt", 1)
	if a.cnt < 1 {
		emit(http.StatusBadRequest, nil, fmt.Sprintf("'cnt' must be positive, given '%d'", a.cnt))
	}
	if a.cnt > 1 && len(a.names) > 1 {
		emit(http.StatusBadRequest, nil, "chunked transfer not possible for multiple files")
	}
	a.idx = getInt("idx", 1)
	if a.idx < 1 {
		emit(http.StatusBadRequest, nil, fmt.Sprintf("'idx' must be positive, given '%d'", a.idx))
	}
	a.size = getInt("size", 0)
	if a.size < 0 {
		emit(http.StatusBadRequest, nil, fmt.Sprintf("'size' must not be negative, given '%d'", a.size))
	}
	a.md5 = strings.ToLower(q.Get("md5"))
	a.token = q.Get("t")
	if a.token == "" { //没有token的话，用来源地址和上传文件名创建一个，是否需要鉴权由使用者决定，上传服务不关心。
		h, _, _ := net.SplitHostPort(r.RemoteAddr)
		target := fmt.Sprintf("%s:%s", h, a.names[0])
		a.token = fmt.Sprintf("%x", md5.Sum([]byte(target)))
	}
	return &a
}

func (uh uploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if uh.cfg.CORS {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Methods", "DELETE, POST, GET, OPTIONS")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	var code int
	var data, mesg string
	je := json.NewEncoder(w)
	defer func() {
		if e := recover(); e != nil {
			err := trace(e)
			switch hr := err.Err().(type) {
			case httpReply:
				code = hr.Code
				mesg = hr.Mesg
			default:
				code = http.StatusInternalServerError
				data = strings.Join(err.Stack(), "\n")
				mesg = err.Err().Error()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		err := je.Encode(map[string]any{"code": code, "data": data, "mesg": mesg})
		if err != nil {
			fmt.Fprintf(os.Stderr, "goup:ServeHTTP: %v\n", err)
		}
	}()
	ua := getUploadArgs(r)
	if uh.auth != nil {
		if err := uh.auth(ua.token, r); err != nil {
			code = http.StatusForbidden
			mesg = err.Error()
			return
		}
	}
	code, data = uh.recv(ua)
	switch code {
	case http.StatusContinue:
		mesg = "awaiting next chunk"
	case http.StatusOK:
		data = ""
		mesg = "file uploaded successfully"
	case http.StatusMultiStatus:
		mesg = "multiple status reported"
	case http.StatusBadRequest, http.StatusNotFound, http.StatusRequestEntityTooLarge:
		mesg = data
		data = ""
	case http.StatusInternalServerError:
		mesg = "internal server error"
	}
}

func (uh *uploadHandler) recv(ua *uploadArgs) (code int, data string) {
	var nexts []string
	wdir := filepath.Join(uh.cfg.Queue, ua.token)
	defer func() {
		del := false
		if err := recover(); err != nil {
			uh.log(trace("%v").Error())
			code = http.StatusInternalServerError
			del = true
		} else if code == http.StatusOK || code == http.StatusMultiStatus {
			del = true
			for _, n := range nexts {
				if n != "0" {
					del = false
					break
				}
			}
		}
		if del {
			if err := os.RemoveAll(wdir); err != nil {
				uh.log("uploadCleanUp: %v", err)
			}
		}
	}()
	assert(os.MkdirAll(wdir, 0777))
	save := func(name string, src io.Reader) (code int, stat string) {
		fn := fmt.Sprintf("%s.chunk_%d_of_%d", name, ua.idx, ua.cnt)
		fn = filepath.Join(wdir, fn)
		f, err := os.Create(fn)
		assert(err)
		defer func() {
			assert(f.Close())
			if stat != "" {
				os.Remove(fn)
				code = http.StatusBadRequest
				return
			}
			for i := 1; i <= ua.cnt; i++ {
				chunk := fmt.Sprintf("%s.chunk_%d_of_%d", name, i, ua.cnt)
				_, err := os.Stat(filepath.Join(wdir, chunk))
				if err != nil {
					code = http.StatusContinue
					stat = strconv.Itoa(i)
					return
				}
			}
			ffn := filepath.Join(uh.cfg.Store, name)
			tmpfn := filepath.Join(uh.cfg.Store, "."+name)
			g, err := os.Create(tmpfn)
			assert(err)
			defer func() {
				assert(g.Close())
				st, err := os.Stat(tmpfn)
				assert(err)
				size := st.Size()
				if size == 0 {
					os.Remove(tmpfn)
					code = http.StatusBadRequest
					stat = "empty upload"
				} else if size > uh.cfg.Limit {
					os.Remove(tmpfn)
					code = http.StatusRequestEntityTooLarge
					stat = "file too large"
				} else {
					if err := os.Rename(tmpfn, ffn); err != nil {
						if !os.IsNotExist(err) {
							panic(err)
						}
						//忽略tmpfn找不到的错误，因为这种情况基本是由于短时间内连续上传同一个文件导致
					}
					code = http.StatusOK
					stat = "0"
				}
			}()
			for i := 1; i <= ua.cnt; i++ {
				chunk := fmt.Sprintf("%s.chunk_%d_of_%d", name, i, ua.cnt)
				func() {
					c, err := os.Open(filepath.Join(wdir, chunk))
					assert(err)
					defer c.Close()
					_, err = io.Copy(g, c)
					assert(err)
				}()
			}
		}()
		var h hash.Hash
		var m io.Writer
		if ua.md5 != "" {
			h = md5.New()
			m = io.MultiWriter(f, h)
		} else {
			m = f
		}
		n, err := io.Copy(m, src)
		assert(err)
		if ua.size > 0 && int64(ua.size) != n {
			stat = "size mismatch"
			return
		}
		if h != nil {
			chk := fmt.Sprintf("%x", h.Sum(nil))
			if ua.md5 != chk {
				stat = "md5 mismatch"
			}
		}
		return
	}
	ok := func() bool {
		if code != http.StatusContinue && code != http.StatusOK {
			return false
		}
		nexts = append(nexts, data)
		return true
	}
	switch fs := ua.files.(type) {
	case string:
		code, data = save(ua.names[0], bytes.NewBufferString(fs))
		if !ok() {
			return
		}
	case io.Reader:
		code, data = save(ua.names[0], fs)
		if !ok() {
			return
		}
	case []*multipart.FileHeader:
		for i, h := range fs {
			func() {
				f, err := h.Open()
				assert(err)
				defer f.Close()
				code, data = save(ua.names[i], f)
			}()
			if !ok() {
				return
			}
		}
	}
	fp := filepath.Join(uh.cfg.Store, ua.names[0])
	switch len(nexts) { //表示客户端并未提供file参数
	case 0:
		tp := filepath.Join(wdir, ua.names[0]+".chunk_%d_of_%d")
		missing := 0
		wip := false
		for i := 1; i <= ua.cnt; i++ {
			_, err := os.Stat(fmt.Sprintf(tp, i, ua.cnt))
			if err != nil {
				if missing == 0 {
					missing = i
				}
				continue
			}
			wip = true
		}
		if wip {
			if missing > 0 {
				return http.StatusContinue, strconv.Itoa(missing)
			}
			return http.StatusOK, "0"
		}
		f, err := os.Open(fp)
		if err != nil {
			return http.StatusNotFound, "file not found"
		}
		defer f.Close()
		if ua.md5 != "" && ua.cnt == 1 && ua.idx == 1 {
			h := md5.New()
			_, err := io.Copy(h, f)
			assert(err)
			chk := fmt.Sprintf("%x", h.Sum(nil))
			if ua.md5 != chk {
				return http.StatusBadRequest, "file md5 mismatch"
			}
		}
		return http.StatusOK, "0"
	case 1:
		if nexts[0] == "0" { //最后一片已经收到
			retry := 0
			for {
				_, err := os.Stat(fp)
				if err == nil {
					break
				}
				retry++
				if retry >= 600 { //最多等待1分钟，事实上组合文件片速度应当非常快
					return http.StatusGatewayTimeout, "file processing timeout"
				}
				time.Sleep(100 * time.Millisecond)
			}
			return http.StatusOK, "0"
		}
		return http.StatusContinue, nexts[0]
	default:
		return http.StatusMultiStatus, strings.Join(nexts, ",")
	}
}
