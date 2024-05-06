def setNotImplementedError(function_name: str):
    raise NotImplementedError(f"{function_name}() is missing code.")


def str_to_float(string_value: str) -> float:
    numeric_string = ''.join(filter(str.isdigit, string_value))  # 过滤出字符串中的数字部分
    float_value = float(numeric_string)  # 将纯数字字符串转换为浮点数

    return float_value
