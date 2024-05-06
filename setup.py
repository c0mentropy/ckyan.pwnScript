from setuptools import setup, find_packages
setup(
      name = 'pwn-ckyan',
      version = '2.1.1',
      author = 'ckyan',
      author_email = "comentropy@foxmail.com",
      description = "pwnScript",
      packages=find_packages(),
      install_requires=[
        'pwntools',  # 你需要的依赖
        # 在这里列出其他依赖项
    ],
    entry_points={
        'console_scripts': [
            'pwnScript=ckyan.pwnScript:args_parser',  # 将 pwnscript 作为命令行工具安装
        ],
    },
)

