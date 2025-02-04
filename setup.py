from setuptools import setup, Extension, find_packages

setup(
    name="ElectroCrypto",
    version="1.0.2dev8",
    description="Fast and Portable Cryptography Extension Library for Electrogram",
    long_description="Hello",
    long_description_content_type="text/markdown",
    url="https://github.com/5hojib",
    download_url="https://github.com/5hojib/ElectroCrypto/releases/latest",
    author="5hojib",
    author_email="yesiamshojib@gmail.com",
    license="LGPLv3+",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: C",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: Implementation",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Internet",
        "Topic :: Communications",
        "Topic :: Communications :: Chat",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    python_requires="~=3.9",
    packages=find_packages(),
    test_suite="tests",
    zip_safe=False,
    ext_modules=[
        Extension(
            "tgcrypto",
            sources=[
                "tgcrypto/tgcrypto.c",
                "tgcrypto/aes256.c",
                "tgcrypto/ige256.c",
                "tgcrypto/ctr256.c",
                "tgcrypto/cbc256.c"
            ]
        )
    ]
)
