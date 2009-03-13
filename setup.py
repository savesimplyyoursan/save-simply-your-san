#!/usr/bin/env python

"""
Python distutils setup script for Save Simply your SAN.

This code was originally contributed by Anthony FOIGNANT.

@author: Anthony FOIGNANT
"""

###################
# Imported modules
###################


from distutils.core import setup

###################
# Setup
###################

setup(name = 'SaveSimplyyourSan',
      version = '0.93',
      license = 'GNU GPL v2',
      url = 'http://code.google.com/p/save-simply-your-san/',
      author = 'Anthony FOIGNANT',
      author_email = 'antispameu-san@yahoo.fr',
      description = "A simple tool which make the configuration's backup of your SAN switches simple and easy. It actually works with Cisco, Brocade and McData switches and allows you to get the configuration of your switch by SCP or FTP. You don't need to install or configure a SSH or a FTP server on your computer.",
      packages = ['SaveSimplyyourSAN'])

