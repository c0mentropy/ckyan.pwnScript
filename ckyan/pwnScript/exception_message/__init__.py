class Message:
    def __init__(self):
        self.language = "en_US"


class ZhCNMessage(Message):
    def __init__(self):
        super().__init__()
        self.language = "zh_CN"
        self.missing_key_documents = "缺少关键文件参数。"
        self.file_not_exist = "文件不存在。"
        self.remote_unreachable = "远程地址无法访问。"


class EnUSMessage(Message):
    def __init__(self):
        super().__init__()
        self.language = "en_US"
        self.missing_key_documents = "Missing key documents."
        self.file_not_exist = "File does not exist."
        self.remote_unreachable = "The remote address is unreachable."


exception_message = Message()

if exception_message.language == "en_US":
    exception_message = EnUSMessage()
else:
    exception_message = ZhCNMessage()