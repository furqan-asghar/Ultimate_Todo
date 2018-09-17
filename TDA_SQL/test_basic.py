# -*- coding: utf-8 -*-
"""
Created on Fri Aug 17 17:07:01 2018

@author: root
"""

import unittest
import os
import json
from rest_server_sql import db

class TodoListAPI(unittest.TestCase):
  
  def setUp(self):
    
    self.app = create_app(config_name="testing")
    with self.app.app_context():
      db.create_all()
      
      