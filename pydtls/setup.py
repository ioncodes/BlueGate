#!/usr/bin/env python
# PyDTLS setup script.

# Copyright 2017 Ray Brown
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# The License is also distributed with this work in the file named "LICENSE."
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""PyDTLS setup script

Install or create a distribution of the PyDTLS package.
"""

from os import path, remove
from shutil import copy2, rmtree
from argparse import ArgumentParser
from pickle import dump, load
from setuptools import setup

NAME = "Dtls"
VERSION = "1.2.3"

if __name__ == "__main__":
    # Full upload sequence for new version:
    #    1. python setup.py bdist_wheel
    #    2. python setup.py bdist_wheel -p win32
    #    3. python setup.py bdist_wheel -p win_amd64
    #    4. twine upload dist/*

    parser = ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("command", nargs="*")
    parser.add_argument("-p", "--plat-name")
    args = parser.parse_known_args()[0]
    dist = "bdist_wheel" in args.command and not args.help
    plat_dist = dist and args.plat_name
    if dist:
        from pypandoc import convert
        long_description = convert("README.md", "rst")\
                           .translate({ord("\r"): None})
        with open("README.rst", "wb") as readme:
            readme.write(long_description)
    else:
        #long_description = open("README.rst").read()
	long_description = ""
    top_package_plat_files_file = "dtls_package_files"
    if dist:
        if plat_dist:
            prebuilt_platform_root = "dtls/prebuilt"
            if args.plat_name == "win32":
                platform = "win32-x86"
            elif args.plat_name == "win_amd64":
                platform = "win32-x86_64"
            else:
                raise ValueError("Unknown platform")
            prebuilt_path = prebuilt_platform_root + "/" + platform
            config = {"MANIFEST_DIR": prebuilt_path}
            execfile(prebuilt_path + "/manifest.pycfg", config)
            top_package_plat_files = map(lambda x: prebuilt_path + "/" + x,
                                         config["FILES"])
            # Save top_package_plat_files with the distribution archive
            with open(top_package_plat_files_file, "wb") as fl:
                dump(top_package_plat_files, fl)
        else:
            top_package_plat_files = []
    else:
        # Load top_package_files from the distribution archive, if present
        try:
            with open(top_package_plat_files_file, "rb") as fl:
                top_package_plat_files = load(fl)
        except IOError:
            top_package_plat_files = []
    top_package_extra_files = ["NOTICE",
                               "LICENSE",
                               "README.md",
                               "ChangeLog"] + top_package_plat_files
    if dist:
        for extra_file in top_package_extra_files:
            copy2(extra_file, "dtls")
    top_package_extra_files = [path.basename(f)
                               for f in top_package_extra_files]
    setup(name=NAME,
          version=VERSION,
          description="Python Datagram Transport Layer Security",
          author="Ray Brown",
          author_email="code@liquibits.com",
          url="https://github.com/rbit/pydtls",
          license="Apache-2.0",
          classifiers=[
              'Development Status :: 5 - Production/Stable',
              'Intended Audience :: Developers',
              'Topic :: Security :: Cryptography',
              'Topic :: Software Development :: Libraries :: Python Modules',
              'License :: OSI Approved :: Apache Software License',
              'Operating System :: POSIX :: Linux',
              'Operating System :: Microsoft :: Windows',
              'Programming Language :: Python :: 2.7',
          ],
          long_description=long_description,
          packages=["dtls", "dtls.demux", "dtls.test"],
          package_data={"dtls": top_package_extra_files,
                        "dtls.test": ["makecerts",
                                      "makecerts_ec.bat",
                                      "openssl_ca.cnf",
                                      "openssl_server.cnf",
                                      "certs/*.pem"]},
          data_files=[('', [top_package_plat_files_file])] if plat_dist else []
    )
    if dist:
        remove("README.rst")
        for extra_file in top_package_extra_files:
            remove("dtls/" + extra_file)
        if plat_dist:
            remove(top_package_plat_files_file)
        rmtree("Dtls.egg-info", True)
        rmtree("build", True)
