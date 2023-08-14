package lingshulian

// 基础响应
type Resp struct {
	Stat string      `json:"status"`  // 状态字符串
	Code int         `json:"code"`    // HTTP状态码
	Msg  string      `json:"message"` // 提示&错误信息
	Data interface{} `json:"data"`    // 返回数据
	// Err  interface{} `json:"error"`   // ?
}

// 文件信息
type File struct {
	Fileid string `json:"file_id"`      // 文件id
	Thumb  any    `json:"thumb_url"`    // 缩略图链接 null/String
	Name   string `json:"name"`         // 名称 (带路径)
	Size   int    `josn:"size"`         // 大小 b
	Modify string `json:"modify_time"`  // 修改时间
	Create string `json:"created_time"` // 创建时间
}

// 文件列表
type Filelist struct {
	List []File `json:"list"`
	Meta struct {
		Pagin struct {
			Total       int    `json:"total"`        // 总页数
			Count       int    `json:"count"`        // 同上?
			PerPage     string `json:"per_page"`     // 最大文件数限制 35
			CurrentPage int    `json:"current_page"` // 当前页数
			TotalPage   int    `json:"total_pages"`  // 总页数
			// Link        struct {
			// 	Previous string `json:"previous"` // ?
			// 	Next     string `json:"next"`     // ?
			// } `json:"links"`
		} `json:"pagination"`
	} `json:"meta"`
}

// 上传会话
type Session struct {
	SecId  string `json:"secret_id"`  // 访问Id
	SecKey string `json:"secret_key"` // ?
	Url    string `json:"upload_url"` // 上传地址 https://s3-us-east-1.ossfiles.com/{Bucket}/{Key}
	Bucket string `json:"bucket"`     // 存储桶
	Key    string `json:"key"`        // 路径
	ExpTo  int    `json:"expire_to"`  // 过期时间 Unix时间戳
}

// 创建目录 POST 'file' DATA 'File'
// type Mkfile struct {
// 	Name string `json:"name"` // 目录名称
// }

// 上传文件 POST 'upload/getUploadSecret' DATA 'Upload_ret'
type Upload struct {
	Name  string `json:"file_name"` // 文件名
	Sha1  string `json:"sha1"`      // ?
	Size  string `json:"size"`      // 文件大小 b
	Thumb int    `json:"thumb"`     // 是否附带缩略图 0:false 1:true
	Dir   string `json:"to_file"`   // 目标目录
}
type Upload_ret struct {
	File  Session `json:"file"`  // 文件
	Thumb Session `json:"thumb"` // 缩略图
}

// 请求信息 PUT Session.Url BODY File 文档 https://www.lingshulian.com/help-document?d_id=42f278a936d6cb87d67e1ace4cdcc16b
// Authorization:
//     AWS4-HMAC-SHA256
//     Credential={Session.SecId}/{YYYYMMDD}/us-east-1/s3/aws4_request,
//     SignedHeaders=host;x-amz-content-sha256;x-amz-date,
//     Signature=f5e07627cc39b90522c187b8034727be79e3830ebd1c3f43ebd20b2944117d7a
// X-Amz-Content-Sha256:
//     Body checksum
// X-Amz-Date:
//     20230806T124554Z

// 下载文件 GET 'file/download?file_name=文件完整路径' DATA Download
type Download struct {
	Url string `json:"download_url"` // 下载链接
}

// 移动文件 PUT 'file/move'
// type Move struct {
// 	To   string   `json:"move_to"`   // 移动到
// 	File []string `json:"move_file"` // 文件列表
// }

// 登录请求 POST 'https://api.lingshulian.com/api/auth/token/login' DATA Login_ret
//
//	type Login struct {
//		Usr      int    `json:"account"`      // 用户名&手机号
//		Pwd      string `json:"password"`     // 密码
//		CaptCode string `json:"captcha_code"` // 选择图片
//		CaptKey  string `json:"captcha_key"`  // 验证会话
//	}
type Login struct {
	Type    string `json:"token_type"`   // 账号类型 Bearer
	Expires int    `json:"expires"`      // 有效时间 43200秒 12小时
	Token   string `json:"access_token"` // 验证密钥
}

// 人机验证 GET 'https://api.lingshulian.com/api/auth/captcha/login'
type Captcha struct {
	Type string `json:"hint"`        // 类型 '铅笔'
	Img  string `json:"image"`       // 图片 base64
	Key  string `json:"captcha_key"` // 验证会话
}

// 百度AI图片类型识别
type ImgType struct {
	Id     float64 `json:"log_id"`
	Result []struct {
		Name  string  `json:"name"`
		Score float64 `json:"score"`
	} `json:"results"`
}
