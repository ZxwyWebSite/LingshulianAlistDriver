package lingshulian

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/alist-org/alist/v3/drivers/base"
	"github.com/alist-org/alist/v3/internal/model"
	"github.com/alist-org/alist/v3/pkg/utils"
	"github.com/go-resty/resty/v2"
)

// 全局变量
var (
	// 常用错误信息
	// errs_cantresolve = errors.New(`无法解析返回数据`)
	stat_success = `success` // 请求成功
	// msg_needcapt = `您没有权限进行下载文件`
	errs_noauth    = errors.New(`未填写授权码`) // 未授权
	errs_emptyfile = errors.New(` Code: 422, Msg: 禁止上传空文件`)
	// 预编译正则表达式
	// reg0, _ = regexp.Compile(`$`)    // 末尾添加时区 +08:00
	reg1, _ = regexp.Compile(`/$`)   // 去除末尾斜杠 path/folder/ -> path/folder
	reg2, _ = regexp.Compile(`^.+/`) // 去除开头路径 path/to/file -> file
	// 验证码图片坐标
	xyz = [9][4]int{
		{0, 0, 100, 100},     // 0 上左
		{100, 0, 200, 100},   // 1 上中
		{200, 0, 300, 100},   // 2 上右
		{0, 100, 100, 200},   // 3 中左
		{100, 100, 200, 200}, // 4 中中
		{200, 100, 300, 200}, // 5 中右
		{0, 200, 100, 300},   // 6 下左
		{100, 200, 200, 300}, // 7 下中
		{200, 200, 300, 300}, // 8 下右
	}
	// 验证码识别类型
	ctype = map[string]string{
		`斑马线`: `banmaxian`,
		`背包`:  `beibao`,
		`灯笼`:  `denglong`,
		`电动车`: `diandongche`,
		`电脑`:  `diannao`,
		`耳机`:  `erji`,
		`房子`:  `fangzi`,
		`飞机`:  `feiji`,
		`高铁`:  `gaotie`,
		`公交车`: `gongjiaoche`,
		`红绿灯`: `honglvdeng`,
		`猴子`:  `houzi`,
		`篮球`:  `lanqiu`,
		`猫`:   `mao`,
		`帽子`:  `maozi`,
		`墨镜`:  `mojing`,
		`铅笔`:  `qianbi`,
		`消防栓`: `xiaofangshuan`,
	}
	// 外链地址缓存 (['文件路径']{'文件外链', '过期时间'})
	flinks = make(map[string][2]string)
	// 验证码任务锁 (同时只允许一个验证码解决任务存在，防止触发Api并发限制)
	captlock = false
)

// 接口列表
const (
	// 棱束链
	lsl_base         = `https://api.lingshulian.com/api/` // 根URL
	lsl_file         = `front/file`                       // 文件信息
	lsl_file_down    = `front/file/download`              // 文件下载
	lsl_file_move    = `front/file/move`                  // 文件移动
	lsl_file_copy    = `front/file/copy`                  // 文件复制
	lsl_file_fgus    = `front/upload/getUploadSecret`     // 获取上传会话
	lsl_file_captcha = `auth/captcha/private/download`    // 外链验证码
	lsl_auth_login   = `auth/token/login`                 // 用户登录
	lsl_auth_captcha = `auth/captcha/login`               // 登录验证码
	// 百度
	// api_imgtype = `https://aip.baidubce.com/rpc/2.0/ai_custom/v1/classification/zxwy_jdtpfl`
	// api_bdtoken = `24.acfa313066748ac08a388db97a170d34.2592000.1694050061.282335-37354517`
)

// 添加棱束链验证信息 (网络请求中间件)
func (d *Lingshulian) addAuth(req *resty.Request) {
	req.SetHeaders(map[string]string{
		`Auth-Lingshulian`: d.UserType + ` ` + d.Auth,
		`Origin`:           `https://console.lingshulian.com`,
		`Referer`:          `https://console.lingshulian.com/`,
	})
}

// 新网络请求 ['返回类型'] ('方法', '地址', '返回', ...'参数') ('错误')
func request2[T any](method string, url string, out T, callback ...base.ReqCallback) error {
	req := base.RestyClient.R()
	req.SetHeaders(map[string]string{
		`User-Agent`: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.188`,
		`Accept`:     `application/json, text/plain, */*`,
	})
	req.SetResult(out)
	for _, v := range callback {
		v(req)
	}
	// if callback != nil {
	// 	callback(req)
	// }
	resp, err := req.Execute(method, url)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return errors.New(resp.String())
	}
	return nil
}

// 请求Api ('方法', '路径', '回调', '是否返回Data') ('Data', '错误')
func (d *Lingshulian) request(method string, path string, callback base.ReqCallback, out interface{}) ([]byte, error) {
	// utils.Log.Infof(`[lingshulian_request] method: %v, path: %v`, method, path)
	u := "https://api.lingshulian.com/api/front/" + path
	req := base.RestyClient.R()
	req.SetHeaders(map[string]string{
		"Auth-Lingshulian": d.UserType + ` ` + d.Auth,
		"Accept":           "application/json, text/plain, */*",
		"User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.188",
		"Origin":           "https://console.lingshulian.com",
		"Referer":          "https://console.lingshulian.com/",
	})
	var r Resp
	req.SetResult(&r)
	if callback != nil {
		callback(req)
	}
	resp, err := req.Execute(method, u)
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, errors.New(resp.String())
	}
	if r.Code != 200 || r.Stat != stat_success {
		return nil, fmt.Errorf(` Code: %v, Msg: %v`, r.Code, r.Msg)
	}
	if out != nil && r.Data != nil {
		var marshal []byte
		marshal, err = json.Marshal(r.Data)
		if err != nil {
			return nil, err
		}
		return marshal, nil
		// utils.Log.Infof(`[lingshulian_request] marshal: %v`, string(marshal))
		// err = json.Unmarshal(marshal, out)
		// if err != nil {
		// 	return err
		// }
		// utils.Log.Infof(`[lingshulian_request] out: %v`, out)
	}
	// return errs_cantresolve
	return nil, nil
}

// 解析文件列表
func objectToObj(f File) *model.Object {
	// reg0, _ := regexp.Compile(`$`) // 在末尾添加时区 +08:00
	// reg1, _ := regexp.Compile(`/$`)   // 去除末尾斜杠 path/folder/ -> path/folder
	// reg2, _ := regexp.Compile(`^.+/`) // 去除开头路径 path/to/file -> file
	// t, _ := time.Parse(`2006-01-02 15:04:05Z07:00`, reg0.ReplaceAllString(f.Modify, `+08:00`))
	t, _ := time.Parse(`2006-01-02 15:04:05Z07:00`, f.Modify+`+08:00`)
	file := reg1.ReplaceAllString(f.Name, ``) // 文件位置 path/to/file.jpg
	fname := reg2.ReplaceAllString(file, ``)  // 文件名称 file.jpg
	fpath := reg2.FindString(file)            // 文件路径 path/to/
	// isdir, _ := regexp.MatchString(`.+/$`, f.Name)
	return &model.Object{
		ID:       f.Fileid,
		Path:     fpath,
		Name:     fname,
		Size:     int64(f.Size),
		Modified: t,
		IsFolder: f.Size == 0,
	}
}

// 获取文件路径 Path+Name+IsDir
func getRealFile(f model.Obj) string {
	name := f.GetPath() + f.GetName()
	if f.IsDir() {
		name += `/`
	}
	return name
}

// 判断是否为目录 (如果是 则在尾部添加反斜杠)
func getIsDir(f model.Obj) string {
	if f.IsDir() {
		return `/`
	}
	return ``
}

// func objectToJson(f, t any) error {
// 	var (
// 		marshal []byte
// 		err     error
// 	)
// 	marshal, err = json.Marshal(f)
// 	if err != nil {
// 		return err
// 	}
// 	err = json.Unmarshal(marshal, &t)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// 映射请求Data到结构体
func getData[T any](f Resp, t T) error {
	if f.Code != 200 || f.Stat != stat_success {
		return fmt.Errorf(` Code: %v, Msg: %v`, f.Code, f.Msg)
	}
	marshal, err := json.Marshal(f.Data)
	if err != nil {
		return err
	}
	return json.Unmarshal(marshal, t)
}

// 判断是否需要登录 () ('IsNeed')
// func (d *Lingshulian) needLogin() bool {
// 	t, e := time.Parse(time.RFC3339, d.UserTokenExp)
// 	if e != nil {
// 		return true
// 	}
// 	return time.Now().After(t)
// }

// 判断是否超过指定时间 ('时间字符串') ('是否到期')
func isAfter(s string) bool {
	t, e := time.Parse(time.RFC3339, s)
	// 解析错误或时间未设置 继续操作覆盖旧数据
	if e == nil {
		// 解析成功 判断是否到期
		if time.Now().Before(t) {
			return false
		}
	}
	return true
}

// 生成到期时间 ('延时(秒)') ('到期时间')
func getExpStr(i int) string {
	return time.Now().Add(time.Duration(i) * time.Second).Format(time.RFC3339)
}

// 模拟登录 ('账号', '密码') ('错误')
func (d *Lingshulian) doLogin() error {
	// 判断是否需要登录
	if !isAfter(d.UserTokenExp) {
		return nil
	}
	// t, e := time.Parse(time.RFC3339, d.UserTokenExp)
	// if e == nil {
	// 	if time.Now().Before(t) {
	// 		return nil
	// 	}
	// }
	// utils.Log.Warnf(`[Login_Init] User: %v, Pass: %v`, user, password)
	// 创建会话
	var ret Resp
	err := request2(http.MethodGet, lsl_base+lsl_auth_captcha, &ret, func(req *resty.Request) {
		req.SetHeaders(map[string]string{
			`Origin`:  `https://www.lingshulian.com`,
			`Referer`: `https://www.lingshulian.com/`,
		})
	})
	if err != nil {
		return err
	}
	var session Captcha
	err = getData(ret, &session)
	if err != nil {
		return err
	}
	// utils.Log.Warnf(`[Login_Captcha] Type: %v, Key: %v`, session.Type, session.Key)
	// 解决验证码
	res, err := d.solveCap(session.Img, session.Type)
	if err != nil {
		return err
	}
	// utils.Log.Warnf(`[Login_Result] Res: %v`, res)
	// 获取Token
	var ret2 Resp
	err = request2(http.MethodPost, lsl_base+lsl_auth_login, &ret2, func(req *resty.Request) {
		req.SetBody(base.Json{
			`account`:      d.User,
			`password`:     d.Pass,
			`captcha_code`: res,
			`captcha_key`:  session.Key,
		})
	})
	if err != nil {
		return err
	}
	var userdata Login
	err = getData(ret2, &userdata)
	if err != nil {
		return err
	}
	// utils.Log.Warnf(`[Login_Success] Type: %v, Exp: %v, Key: %v`, userdata.Type, userdata.Expires, userdata.Token)
	// 保存配置
	d.Auth = userdata.Token
	d.UserType = userdata.Type
	d.UserTokenExp = getExpStr(userdata.Expires)
	return nil
}

// 解决验证码 ('Base64编码图片', '识别类型') ('结果', '错误')
func (d *Lingshulian) solveCap(img64, need string) (string, error) {
	// 检查验证码任务锁
	for i := 0; true; i++ {
		if !captlock {
			captlock = true
			break
		}
		if i > 20 {
			return ``, errors.New(`等待其它验证码任务超时`)
		}
		time.Sleep(time.Second)
	}
	// 刷新ApiKey
	err := d.getAccesstoken()
	if err != nil {
		captlock = false
		return ``, err
	}
	// 去除数据类型头部
	img_base64 := strings.Replace(img64, `data:image/jpeg;base64,`, ``, 1)
	// 解码Base64
	img_decode, err := base64.StdEncoding.DecodeString(img_base64)
	if err != nil {
		captlock = false
		return ``, err
	}
	// 解码图片
	img, err := jpeg.Decode(bytes.NewReader(img_decode))
	if err != nil {
		captlock = false
		return ``, err
	}
	// 图片裁剪
	var imgs [9]string
	for i := 0; i < 9; i++ {
		cut := img.(*image.YCbCr).SubImage(image.Rect(xyz[i][0], xyz[i][1], xyz[i][2], xyz[i][3])).(*image.YCbCr)
		buf := bytes.NewBuffer(nil)
		err := jpeg.Encode(buf, cut, nil)
		if err != nil {
			captlock = false
			return ``, err
		}
		imgs[i] = base64.StdEncoding.EncodeToString(buf.Bytes())
	}
	// 类型识别
	var num int
	var ret string
	for i := 0; i < 9; i++ {
		itype, err := d.getImageType(imgs[i])
		if err != nil {
			captlock = false
			return ``, err
		}
		if itype == ctype[need] {
			num++
			ret += fmt.Sprint(i)
		}
		// utils.Log.Warnf(`[Login_Type] Num: %v, Type: %v, Ret: %v`, i, itype, ret)
		if num >= 4 {
			break
		}
	}
	if num < 4 {
		captlock = false
		return ``, errors.New(`验证码识别结果不完整`)
	}
	captlock = false
	return ret, nil
}

// 百度AI识图 ('Base64编码图片') ('类型', '错误')
func (d *Lingshulian) getImageType(img64 string) (string, error) {
	var ret ImgType
	for i := 0; true; i++ {
		err := request2(http.MethodPost, d.BdApiAddr+`?access_token=`+d.BdApiToken, &ret, func(req *resty.Request) {
			req.SetHeader(`Content-Type`, `application/json`)
			req.SetBody(map[string]any{
				`image`:   img64,
				`top_num`: 1,
			})
		})
		if err != nil {
			return ``, err
		}
		// 判断是否有返回结果
		if len(ret.Result) >= 1 {
			break
		}
		if i > 5 {
			return ``, errors.New(`识图Api调用失败且超出最大重试次数`)
		}
		time.Sleep(time.Second)
	}
	return ret.Result[0].Name, nil
}

// 获取百度Api Access_token ('API Key', 'Secret Key') ('Err')
func (d *Lingshulian) getAccesstoken() error {
	// 判断是否需要刷新访问Token
	if !isAfter(d.BdApiTokenExp) {
		return nil
	}
	// t, e := time.Parse(time.RFC3339, d.BdApiTokenExp)
	// if e == nil {
	// 	if time.Now().Before(t) {
	// 		return nil
	// 	}
	// }
	// 判断是否填写必要参数
	if d.BdAppKey == `` {
		return errors.New(`未填写BdAppKey(API Key)`)
	}
	if d.BdAppSecKey == `` {
		return errors.New(`未填写BdAppSecKey(Secret Key)`)
	}
	// 通过 AppKey和AppSecKey 获取Token
	type AccessToken struct {
		// Refresh string `json:"refresh_token"` // ?
		Expires int    `json:"expires_in"`   // 过期时间 单位秒
		Token   string `json:"access_token"` // 获取到的 AccessToken
	}
	var ret AccessToken
	err := request2(http.MethodPost, fmt.Sprintf(`https://aip.baidubce.com/oauth/2.0/token?client_id=%v&client_secret=%v&grant_type=client_credentials`, d.BdAppKey, d.BdAppSecKey),
		&ret, func(req *resty.Request) {
			req.SetHeader(`Content-Type`, `application/json`)
		})
	if err != nil {
		return err
	}
	// 保存数据
	d.BdApiToken = ret.Token
	d.BdApiTokenExp = getExpStr(ret.Expires)
	return nil
}

// 获取文件链接 ('文件路径') ('外链', '错误')
func (d *Lingshulian) getLink(fpath string) (string, error) {
	var req Resp
	var down Download
	// 判断是否有缓存
	if v, ok := flinks[fpath]; ok {
		// 判断缓存内容是否过期
		if !isAfter(v[1]) {
			// 未过期直接返回缓存内容
			// utils.Log.Warnf(`[lingshulian_link] UseCache: %v`, v)
			return v[0], nil
		}
	}
	// 直接获取文件外链
	url := lsl_base + lsl_file_down + `?file_name=` + fpath
	err := request2(http.MethodGet, url, &req, d.addAuth)
	if err != nil {
		return ``, err
	}
	err = getData(req, &down)
	if err != nil {
		// 判断错误类型
		if req.Msg != `您没有权限进行下载文件` {
			return ``, err
		}
		utils.Log.Warn(`[lingshulian_link] NeedCaptcha!`)
		// 添加验证码
		var req2 Resp
		err := request2(http.MethodGet, lsl_base+lsl_file_captcha, &req2, d.addAuth)
		if err != nil {
			return ``, err
		}
		var ret Captcha
		err = getData(req2, &ret)
		if err != nil {
			return ``, err
		}
		code, err := d.solveCap(ret.Img, ret.Type)
		if err != nil {
			return ``, err
		}
		// 再次尝试获取外链
		err = request2(http.MethodGet, url+fmt.Sprintf(`&captcha_code=%v&captcha_key=%v`, code, ret.Key), &req, d.addAuth)
		if err != nil {
			return ``, err
		}
		err = getData(req, &down)
		if err != nil {
			return ``, err
		}
	}
	// 保存数据
	flinks[fpath] = [2]string{down.Url, getExpStr(3600)} // 缓存1小时(3600秒)
	return down.Url, nil
}

// 生成 CanonicalRequest ('请求方法', 'URI绝对路径', '查询字符串', '请求头列表', '签名头列表', 'BodySha256值') ('结果')
func makeCanonicalRequest(httpMethod string, uriPath []string, queryStr, reqHeaders map[string]string, signHeaders string, bodySha256 string) string {
	var CanonicalURI string
	for _, v := range uriPath {
		CanonicalURI += (`/` + url.QueryEscape(v))
	}
	var CanonicalQueryString string
	var iCanonicalQueryString int
	for k, v := range queryStr {
		CanonicalQueryString += (url.QueryEscape(k) + `=` + url.QueryEscape(v))
		iCanonicalQueryString++
		if iCanonicalQueryString+1 != len(queryStr) {
			CanonicalQueryString += `&`
		}
	}
	var CanonicalHeaders string
	for k, v := range reqHeaders {
		CanonicalHeaders += (strings.ToLower(k) + `:` + strings.TrimSpace(v) + "\n")
	}
	var SignedHeaders = strings.ToLower(signHeaders)
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", httpMethod, CanonicalURI, CanonicalQueryString, CanonicalHeaders, SignedHeaders, bodySha256)
}

// 计算 HMAC
func makeHMac(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

// 计算 Sha256 ('内容') ('结果')
func getSha256(file []byte) string {
	s := sha256.New()
	s.Write(file)
	return hex.EncodeToString(s.Sum(nil))
}
