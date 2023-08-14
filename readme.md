## ZxwyWebSite/LingshulianAlistDriver
### 简介
+ 棱束链个人存储的Alist驱动
+ 开发中，不保证稳定性
+ 外链获取频率有限制，不建议用于分享文件

### 使用
0. 参考Alist官方文档下载源码
1. 将本仓库内lingshulian文件夹复制到Alist源码的drivers目录，并在all.go中引入lingshulian包
2. 编译运行
3. 进入后台添加存储策略，选择Lingshulian驱动
4. 填写以下信息，其它数据会自动生成，具体描述见meta.go
  + Username: 用户名
  + Password: 密码
  + Baidu_apiaddr: 识图Api地址
  + Baidu_appkey: 应用API Key
  + Baidu_seckey: 应用Secret Key
5. 点击添加，第一次会调用识图Api解决验证码，可能较慢，如无报错即可返回主页使用

### 其它
+ 测试时可使用我提供的Api，但不保证稳定性，建议自行搭建
+ ApiAddr：https://aip.baidubce.com/rpc/2.0/ai_custom/v1/classification/zxwy_jdtpfl
+ AppKey：1QfWcTNM07zXrKom2fNukENw
+ SecKey：VTE2jEiOfWjXWqlpFQt7WPcBYo4RTRIf

### 搭建自己的识图Api
+ 官方文档：https://ai.baidu.com/ai-doc/EASYDL/3kccwnvy6
+ 主页地址：https://ai.baidu.com/easydl/
+ 参考视频：自建百度识图Api教程.mp4
+ (账号无需实名，每月2500次免费调用)
+ 进入主页，点击 [立即使用] → [图像分类]
+ 点击 [训练模型]，随意填写信息，完成后点击下一步
+ 新建数据集，名称随意，点击 [创建并导入]
+ 选择 [有标注信息] → [本地导入] → [上传压缩包]
+ 选择 [以文件夹命名分类]，上传仓库中的 [jiandan.zip]
+ 等待导入完成，选中刚才创建的数据集，点击下一步
+ 将 [选择网络] 改为300-200，开始训练
+ 大约需要2个小时，请耐心等待
+ 完成后点击 [申请发布]
+ 名称随意，接口地址需唯一，其它要求可不填，提交申请
+ 等待审核，机审一般5分钟就过
+ 点击 [服务详情] 查看接口地址 (ApiAddr)，复制备用
+ 点击前往 [控制台]，可能需要重新登录
+ 左侧选择 [公有云部署] → [应用列表]
+ 新建一个应用，名称随便填，默认已选择EasyDL接口
+ 创建完毕后点击 [查看应用详情]
+ API Key即为 (AppKey)，Secret Key即为 (SecKey)
+ 然后填入Alist存储配置就能用了

