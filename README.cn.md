# 文件上传规范

## 调用方式与编码类型

文件上传必须使用POST方法，支持以下三种编码：

1. application/octet-stream：body直接是文件数据
1. multipart/form-data：file是文件数据
1. 除以上两种编码外，默认编码为application/x-www-form-urlencoded，file是文件数据

注意：`multipart/form-data`编码方式不支持文件分片传输/断点续传，需要分片传输请使用其
它两种编码方式。

## 参数

调用参数可以使用GET（URL）/POST（BODY）/COOKIE方式（当BODY为octet-stream时，
参数必须通过URL或COOKIE传递）。参数的优先级从低到高为：COOKIE，BODY，URL。即：
BODY中的同名参数覆盖COOKIE中的，URL上的同名参数覆盖BODY的。

- file：文件数据（可选）
- name：文件名
- cnt：分片数（可选，默认为1）
- idx：当前分片（从1开始，可选，默认为1）
- size：当前分片的字节数（可选）
- md5：当前分片的MD5校验码（可选）
- t：访问令牌

### 状态查询

若调用时没有提供file参数，视为状态查询。此时请求所用的编码应为`application/x-www-form-urlencoded`。
可能的返回为：

- 100：文件还没有传完
- 200：文件没有在传输中，目标文件已经存在
- 404：文件没有在传输中，目标文件不存在
- 400：文件没有在传输中，目标文件MD5校验失败。注意，文件MD5校验有以下条件：
  1. 文件传输已完成
  1. 请求的编码为`application/x-www-form-urlencoded`（缺省为此编码）
  1. 调用者提供了md5参数，且cnt、idx的值均为1（或者不传这两个参数）

详细的返回格式见下文。

## 返回

返回的HTTP状态码统一为200，内容为application/json编码，其格式为一个对象，
包含以下属性：

- code：返回码(int)
  - 100：文件还没有传完
  - 200：文件已经传完
  - 207：传输了多个文件（状态返回在data中）
  - 401：token错误（没有权限）
  - 400：数据错误
  - 404：指定文件不存在（当做进度查询时返回）
  - 413：文件尺寸超过限制
  - 500: 服务器端错误
- data：附加数据（string）
  - 当返回码为100时：为当前缺少的第一个分片
  - 当返回码为207时，为所有文件的下一分片编号（CSV格式），编号为0表示该文件已
    经传输完成。例如：0,2,...表示第一个文件已经传输完成，第二个文件下一片编号
    为2... 以此类推。
  - 当返回码为500时，为错误跟踪（多行文本）
  - 其它返回码时，为空串
- mesg：说明 (string)
