package lingshulian

import (
	"github.com/alist-org/alist/v3/internal/driver"
	"github.com/alist-org/alist/v3/internal/op"
)

type Addition struct {
	// 挂载目录 根目录不填 其它目录例如 '测试/'
	driver.RootPath
	// Field string `json:"field" type:"select" required:"true" options:"a,b,c" default:"a"`
	// 必填数据 用于登录账号
	User        string `json:"username" required:"true"` // 用户名
	Pass        string `json:"password" required:"true"` // 密码
	BdApiAddr   string `json:"baidu_apiaddr"`            // 百度 Api地址
	BdAppKey    string `json:"baidu_appkey"`             // 应用 API Key
	BdAppSecKey string `json:"baidu_seckey"`             // 应用 Secret Key
	// 选填数据 用于开发测试
	BdApiToken string `json:"baidu_apitoken"` // 百度Api Token
	Auth       string `json:"auth"`           // Cookie Authorization
	// 缓存数据 用于保存状态
	UserType      string `json:"cache_usertype"`      // 账号类型
	UserTokenExp  string `json:"cache_usertokenexp"`  // 账号token过期时间
	BdApiTokenExp string `json:"cache_bdapitokenexp"` // 百度token过期时间
}

var config = driver.Config{
	Name:        "Lingshulian", // 注：本驱动为棱束链个人存储提供支持，对象存储请用s3驱动挂载
	DefaultRoot: "",
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &Lingshulian{}
	})
}
