#!/usr/bin/env python

from distutils.core import setup

setup(name='vtapi',
      version='1.4.0',
      description='this library implement virustotal api v2.0',
      author='z.sean.huang',
      author_email='z.sean.huang@gmail.com',
      url='http://github.com/z-sean-huang/VirustotalAPI',
      py_modules=['vtapi'],
      license='MIT',
      platforms=['Any'],
      keywords=["virustotal", "malicious", "virus"],
      install_requires=["requests"],
)
