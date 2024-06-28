from setuptools import setup, find_packages
setup(
      name = 'pwn-ckyan',
      version = '2.1.6',
      author = 'Comentropy Ckyan',
      author_email = "comentropy@foxmail.com",
      description = "pwnScript is a tools for exploiting vuln in ELF files.",
      packages=find_packages(),
      url="https://github.com/c0mentropy/ckyan.pwnScript",
      license='GPL-3.0',
      classifiers=[
        "Programming Language :: Python :: 3",
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)'
    ],
      install_requires=[
        'pwntools',
        'keystone-engine',
        'z3-solver',
        'requests'
    ],
      entry_points={
        'console_scripts': [
            'pwnScript=ckyan.pwnScript.args_parser:args_init'
        ],
    },
)

