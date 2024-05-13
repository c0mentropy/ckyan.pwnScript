import json
import os


from ..log4ck import error


def setNotImplementedError(function_name: str):
    raise NotImplementedError(f"{function_name}() is missing code.")


def str_to_float(string_value: str) -> float:
    numeric_string = ''.join(filter(str.isdigit, string_value))  # 过滤出字符串中的数字部分
    float_value = float(numeric_string)  # 将纯数字字符串转换为浮点数

    return float_value


def create_file_if_not_exists(file_path: str):
    if not os.path.exists(file_path):
        open(file_path, 'w').close()


def read4file(folder_path: str, file_name: str = "") -> str:
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    file_path = os.path.join(folder_path, file_name)
    create_file_if_not_exists(file_path)

    with open(file_path, "r") as file:
        content = file.read()

    return content


def read4json(folder_path: str, file_name: str = "") -> dict:
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    file_path = os.path.join(folder_path, file_name)
    create_file_if_not_exists(file_path)
    datas = {}
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            datas.update(data)
    except Exception as ex:
        # error(f"{str(ex) = }")
        pass
    finally:
        return datas


def save2file(folder_path: str, file_name: str, content: str or bytes, save_or_replace: str = "a"):
    # 判断文件夹是否存在，如果不存在则创建文件夹
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    file_path = os.path.join(folder_path, file_name)

    datas = read4file(folder_path, file_name)
    datas = datas + content

    with open(file_path, save_or_replace) as file:
        file.write(datas)
        file.write("\n")


def save2json(folder_path: str, file_name: str, content: dict, save_or_replace: str = "w"):
    # 判断文件夹是否存在，如果不存在则创建文件夹
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    file_path = os.path.join(folder_path, file_name)

    datas = read4json(folder_path, file_name)
    datas.update(content)

    # 将课程数据写入JSON文件
    with open(file_path, save_or_replace, encoding='utf-8') as file:
        json.dump(datas, file, ensure_ascii=False, indent=4)


class MyDate:
    date_fmt = '[%Y-%m-%d %H:%M:%S]'

    date_fmt_filepath = '%Y-%m-%d'
    # date_fmt_filename = '%Y-%m-%d-%H-%M-%S'
    date_fmt_filename = '%Y-%m-%d-%H-%M'


def get_the_current_date(form: str = "") -> str:
    import datetime
    # 获取当前时间戳
    timestamp = datetime.datetime.now()

    if form == "name":
        date_form = MyDate.date_fmt_filename
    elif form == "path":
        date_form = MyDate.date_fmt_filepath
    else:
        date_form = MyDate.date_fmt

    # 将时间戳转化为指定格式
    formatted_time = timestamp.strftime(date_form)

    # 输出结果
    # print(formatted_time)
    return formatted_time