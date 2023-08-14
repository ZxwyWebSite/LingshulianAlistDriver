package lingshulian

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/alist-org/alist/v3/drivers/base"
	"github.com/alist-org/alist/v3/internal/driver"
	"github.com/alist-org/alist/v3/internal/model"
	"github.com/alist-org/alist/v3/pkg/utils"
	"github.com/go-resty/resty/v2"
)

type Lingshulian struct {
	model.Storage
	Addition
}

func (d *Lingshulian) Config() driver.Config {
	return config
}

func (d *Lingshulian) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *Lingshulian) Init(ctx context.Context) error {
	if d.BdApiAddr == `` {
		return errs_noauth
	}
	// 刷新ApiKey (已迁移至solveCap函数)
	// err := d.getAccesstoken()
	// if err != nil {
	// 	return err
	// }
	// 尝试登录
	err := d.doLogin()
	if err != nil {
		return err
	}
	return nil
}

func (d *Lingshulian) Drop(ctx context.Context) error {
	return nil
}

// 获取文件列表
func (d *Lingshulian) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	// 每个Api请求前尝试登录
	e := d.doLogin()
	if e != nil {
		return nil, e
	}
	var ret Filelist
	pathfmt := func(n string) string {
		if n != `root` {
			return n + `/`
		}
		return ``
	}
	utils.Log.Warnf(`[lingshulian_list] path: %v, name: %v, fmt: %v`, dir.GetPath(), dir.GetName(), dir.GetPath()+pathfmt(dir.GetName()))
	out, err := d.request(http.MethodGet, `file?page=1&limit=100&prefix=`+url.PathEscape(dir.GetPath()+pathfmt(dir.GetName())), nil, true)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(out, &ret)
	if err != nil {
		return nil, err
	}
	sliceConvert := func(srcS []File, convert func(src File) (model.Obj, error)) ([]model.Obj, error) {
		res := make([]model.Obj, 0, len(srcS))
		for i := range srcS {
			if i == 0 && dir.GetName() != `root` {
				continue
			}
			dst, err := convert(srcS[i])
			if err != nil {
				return nil, err
			}
			res = append(res, dst)
		}
		return res, nil
	}
	return sliceConvert(ret.List, func(src File) (model.Obj, error) {
		return objectToObj(src), nil
	})
}

// 获取文件外链
func (d *Lingshulian) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	// 每个Api请求前尝试登录
	e := d.doLogin()
	if e != nil {
		return nil, e
	}
	utils.Log.Warnf(`[lingshulian_link] path: %v, name: %v`, file.GetPath(), file.GetName())
	// var ret Download
	// out, err := d.request(http.MethodGet, `file/download?file_name=`+url.PathEscape(file.GetPath()+file.GetName()), nil, true)
	// if err != nil {
	// 	return nil, err
	// }
	// err = json.Unmarshal(out, &ret)
	// if err != nil {
	// 	return nil, err
	// }
	// return &model.Link{
	// 	URL: ret.Url,
	// }, nil
	link, err := d.getLink(url.PathEscape(file.GetPath() + file.GetName()))
	if err != nil {
		return nil, err
	}
	return &model.Link{
		URL: link,
	}, nil
}

// 创建文件夹
func (d *Lingshulian) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	// 每个Api请求前尝试登录
	e := d.doLogin()
	if e != nil {
		return e
	}
	utils.Log.Warnf(`[lingshulian_mkdir] name: %v`, getRealFile(parentDir)+dirName+`/`)
	_, err := d.request(http.MethodPost, `file`, func(req *resty.Request) {
		req.SetBody(base.Json{
			`name`: getRealFile(parentDir) + dirName + `/`,
		})
	}, nil)
	if err != nil {
		return err
	}
	return nil
}

// 移动文件
func (d *Lingshulian) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	// 每个Api请求前尝试登录
	e := d.doLogin()
	if e != nil {
		return e
	}
	utils.Log.Warnf(`[lingshulian_move] file: %v, to: %v`, []string{getRealFile(srcObj)}, getRealFile(dstDir))
	_, err := d.request(http.MethodPut, `file/move`, func(req *resty.Request) {
		req.SetBody(base.Json{
			`move_file`: []string{getRealFile(srcObj)},
			`move_to`:   getRealFile(dstDir),
		})
	}, nil)
	if err != nil {
		return err
	}
	return nil
}

// 重命名
func (d *Lingshulian) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	// 每个Api请求前尝试登录
	e := d.doLogin()
	if e != nil {
		return e
	}
	utils.Log.Warnf(`[lingshulian_rename] old: %v, new: %v`, getRealFile(srcObj), srcObj.GetPath()+newName+getIsDir(srcObj))
	_, err := d.request(http.MethodPut, `file`, func(req *resty.Request) {
		req.SetBody(base.Json{
			`old_name`: getRealFile(srcObj),
			`new_name`: srcObj.GetPath() + newName + getIsDir(srcObj),
		})
	}, nil)
	if err != nil {
		return err
	}
	return nil
}

// 复制文件
func (d *Lingshulian) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	// 每个Api请求前尝试登录
	e := d.doLogin()
	if e != nil {
		return e
	}
	utils.Log.Warnf(`[lingshulian_copy] file: %v, to: %v`, []string{getRealFile(srcObj)}, getRealFile(dstDir))
	_, err := d.request(http.MethodPost, `file/copy`, func(req *resty.Request) {
		req.SetBody(base.Json{
			`copy_file`: []string{getRealFile(srcObj)},
			`copy_to`:   getRealFile(dstDir),
		})
	}, nil)
	if err != nil {
		return err
	}
	return nil
}

// 删除文件
func (d *Lingshulian) Remove(ctx context.Context, obj model.Obj) error {
	// 每个Api请求前尝试登录
	e := d.doLogin()
	if e != nil {
		return e
	}
	utils.Log.Warnf(`[lingshulian_rm] path: %v`, []string{getRealFile(obj)})
	_, err := d.request(http.MethodDelete, `file`, func(req *resty.Request) {
		// req.SetBody([]string{obj.GetPath() + obj.GetName() + getIsDir(obj)})
		req.SetBody([]string{getRealFile(obj)})
	}, nil)
	if err != nil {
		return err
	}
	return nil
}

// 上传文件 (不支持新建空文件)
func (d *Lingshulian) Put(ctx context.Context, dstDir model.Obj, stream model.FileStreamer, up driver.UpdateProgress) error {
	// 每个Api请求前尝试登录
	e := d.doLogin()
	if e != nil {
		return e
	}
	utils.Log.Warnf(`[lingshulian_upload] Nmae: %v, Size: %v, ToPath: %v, ToName: %v, ToIsDir: %v`, stream.GetName(), stream.GetSize(), dstDir.GetPath(), dstDir.GetName(), dstDir.IsDir())
	// 禁止上传空文件
	if stream.GetSize() == 0 {
		return errs_emptyfile
	}
	// 根据文件Mime类型判断是否有缩略图
	// var (
	// 	// ret   Session
	// 	thumb = 0
	// 	// mimes = []string{`image/jpeg`, `image/png`}
	// )
	// types := make(map[string]any)
	// for _, v := range mimes {
	// 	types[v] = struct{}{}
	// }
	// if _, ok := types[stream.GetMimetype()]; ok {
	// 	thumb = 1
	// }
	// 将文件缓存到buffer
	buf := bytes.NewBuffer(nil)
	_, err := io.Copy(buf, stream)
	if err != nil {
		return err
	}
	// 计算文件SHA1值
	fhash1 := sha1.New()
	// _, err := io.Copy(fhash1, stream)
	// if err != nil {
	// 	return err
	// }
	fhash1.Write(buf.Bytes())
	fsha1 := hex.EncodeToString(fhash1.Sum(nil))
	// 创建上传会话
	var ret Resp
	now := time.Now()
	err = request2(http.MethodPost, lsl_base+lsl_file_fgus, &ret, d.addAuth, func(req *resty.Request) {
		req.SetBody(base.Json{
			`file_name`: stream.GetName(),
			`sha1`:      fsha1,
			`size`:      stream.GetSize(),
			`thumb`:     0,
			`to_file`:   getRealFile(dstDir),
		})
	})
	// utils.Log.Warnf(`[lingshulian_upload] Name: %v, Size: %v, To: %v, Sha: %v`, stream.GetName(), stream.GetSize(), getRealFile(dstDir), fsha1)
	if err != nil {
		return err
	}
	var session Upload_ret
	err = getData(ret, &session)
	if err != nil {
		return err
	}
	// utils.Log.Warnf(`[lingshulian_upload] Session: %v`, session.File)
	// 验证会话是否完整
	if session.File.SecId == `` {
		return errors.New(`会话信息不完整`)
	}
	// 计算文件Sha256值
	fhash256 := sha256.New()
	// _, err = io.Copy(fhash256, stream)
	// if err != nil {
	// 	return err
	// }
	fhash256.Write(buf.Bytes())
	fsha256 := hex.EncodeToString(fhash256.Sum(nil))
	// 生成签名参数
	var (
		ftime1      = now.Format(`20060102T150405Z`)
		ftime2      = now.Format(`20060102`)
		region      = `us-east-1`
		service     = `s3`
		scope       = fmt.Sprintf(`%s/%s/%s/aws4_request`, ftime2, region, service)
		contentType = stream.GetMimetype()
		signheaders = `host;x-amz-content-sha256;x-amz-date`
	)
	signReq := makeCanonicalRequest(http.MethodPut, []string{session.File.Bucket, session.File.Key}, map[string]string{}, map[string]string{
		`Host`:                 `s3-us-east-1.ossfiles.com`,
		`X-Amz-Content-Sha256`: fsha256,
		`X-Amz-Date`:           ftime1,
	}, signheaders, fsha256)
	signStr := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", ftime1, scope, getSha256([]byte(signReq)))
	signKey := hex.EncodeToString(makeHMac(makeHMac(makeHMac(makeHMac(makeHMac([]byte("AWS4"+session.File.SecKey), []byte(ftime2)), []byte(region)), []byte(service)), []byte(`aws4_request`)), []byte(signStr)))
	signAuth := fmt.Sprintf(`AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s`, session.File.SecId, scope, signheaders, signKey)
	// 使用s3协议上传
	// utils.Log.Warnf(`[lingshulian_upload] Bucket: %v, Key: %v, Type: %v`, session.File.Bucket, session.File.Key, contentType)
	// utils.Log.Warnf(`[lingshulian_upload] Auth: %v, Length: %v, Type: %v, Sha256: %v, Date: %v`, signAuth, fmt.Sprint(stream.GetSize()), contentType, fsha256, ftime1)
	return request2(http.MethodPut, session.File.Url, struct{}{}, func(req *resty.Request) {
		req.SetHeaders(map[string]string{
			`Authorization`:        signAuth,
			`Content-Length`:       fmt.Sprint(stream.GetSize()),
			`Content-Type`:         contentType,
			`Origin`:               `https://console.lingshulian.com`,
			`Referer`:              `https://s3-us-east-1.ossfiles.com/`,
			`X-Amz-Content-Sha256`: fsha256,
			`X-Amz-Date`:           ftime1,
		})
		req.SetBody(buf.Bytes()).SetContext(ctx)
	})
}

//func (d *Lingshulian) Other(ctx context.Context, args model.OtherArgs) (interface{}, error) {
//	return nil, errs.NotSupport
//}

var _ driver.Driver = (*Lingshulian)(nil)
