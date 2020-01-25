# lua-binary-protocol-module
可以在LUA中使用table来生成二进制数据协议。

使用LUA的string库中pack，unpack来对协议描述表（table）动态生成对应的序列化，反序列化函数

未经过严格的效率测试，解析时没有对二进制流的进行检测，我的做法是使用pcall调用

支持
boolean
int8
uint8
int16
uint16
int32
uint32
number
string
bytes
table
array
