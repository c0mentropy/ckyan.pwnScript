from setuptools import setup, find_packages
setup(
      name = 'pwn-ckyan',
      version = '2.1.1',
      author = 'ckyan',
      author_email = "comentropy@foxmail.com",
      description = "pwnScript",
      packages=find_packages(),
      install_requires=[
        'pwntools',
        'keystone-engine',
        'z3-solver'
    ],
    entry_points={
        'console_scripts': [
            'pwnScript=ckyan.pwnScript:args_parser',
        ],
    },
)

