# -*- coding: utf-8 -*-
"""
Created on Thu Aug 16 20:11:24 2018

@author: root
"""

from flask import Flask, request, jsonify, make_response
from flask_mongoalchemy import MongoAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from functools import wraps
import os
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret_key'
app.config['MONGOALCHEMY_DATABASE'] = 'todo_app'
app.config['MONGOALCHEMY_CONNECTION_STRING'] = 'mongodb://furqan:qwerty1@ds235251.mlab.com:35251/todo_app'

db = MongoAlchemy(app)

class User(db.Document):
  u_id = db.IntField()
  public_id = db.StringField()
  name = db.StringField()
  password = db.StringField()
  admin = db.BoolField()

class TDA(db.Document):
  
  u_id = db.IntField()
  title = db.StringField()
  desc = db.StringField()
  status = db.BoolField()
  user_id = db.IntField()
  

def token_required(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    token = None
    
    if 'x-access-token' in request.headers:
      token = request.headers['x-access-token']
      
    if not token:
      return jsonify({"message":"Token is missing "}), 401
    
    try:
      data = Serializer(app.config['SECRET_KEY']).loads(token)
      current_user = User.query.filter_by(public_id=data).first()
    
    except:
      return jsonify({'message' : 'Token is invalid!'}), 401
      
    return f(current_user, *args, **kwargs)
  
  return decorated

@app.route('/user',methods=['GET'])
@token_required
def get_all_users(current_user):
  
  if not current_user.admin:
    return jsonify({'Users': 'prohibited for underprivileged'})
  users = User.query.all()
  output = []
  for i in users:
    user_data = {}
    user_data['public_id'] = i.public_id
    user_data['name'] = i.name
    user_data['password'] = i.password
    user_data['admin'] = i.admin
    output.append(user_data)
  return jsonify({'Users': output})

@app.route('/user/<public_id>',methods=['GET'])
#@token_required
def get_one_user(public_id):
  
  #if not current_user.admin:
    #return jsonify({'Users': 'prohibited for underprivileged'})
  
  user = User.query.filter_by(public_id=public_id).first()
  
  if not user:
    return jsonify({'message': 'User not found'})
  
  user_data = {}
  user_data['public_id'] = user.public_id
  user_data['name'] = user.name
  user_data['password'] = user.password
  user_data['admin'] = user.admin
  
  return jsonify({'Users': user_data})

@app.route('/user',methods=['POST'])
@token_required
def create_user(current_user):
  data = request.get_json()
 
  count = len(User.query.all())
  count=count+1  

  hashed_pass = generate_password_hash(data['password'], method='sha256')
  new_user = User(u_id = count, public_id=str(uuid.uuid4()), name=data['name'], password=hashed_pass, admin=False) 
  new_user.save()

  return jsonify({'message' : 'New user added'})

@app.route('/user/<public_id>',methods=['PUT'])
@token_required
def promote_user(public_id, current_user):
  user = User.query.filter_by(public_id=public_id).first()
  
  if not current_user.admin:
    return jsonify({'Users': 'prohibited for underprivileged'})
  
  if not user:
    return jsonify({'message': 'User not found'})
  
  user.admin = True
  user.save()
  return jsonify({'message': 'User Promoted'})

@app.route('/user/<public_id>',methods=['DELETE'])
@token_required
def delete_user(public_id,current_user):
  user = User.query.filter_by(public_id=public_id).first()
  
  if not current_user.admin:
    return jsonify({'Users': 'prohibited for underprivileged'})
  
  if not user:
    return jsonify({'message': 'User not found'})
  
  user.remove()
  return jsonify({'message': 'User Deleted'})

@app.route('/login')
def login():
    auth = request.authorization
    
    if not auth or not auth.username or not auth.password:
      return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm="Login required"'})
    
    user = User.query.filter_by(name=auth.username).first()
    
    if not user:
      return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm="Login required"'})
    
    if check_password_hash(user.password, auth.password):
      token = Serializer(app.config['SECRET_KEY'], expires_in = 3600).dumps(user.public_id)
   
      return jsonify({'token':token.decode('UTF-8') })

    return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm="Login required"'})

@app.route('/todo', methods=['GET'])
@token_required
def get_all_tasks(current_user):
  
  todos = TDA.query.filter_by(user_id=current_user.u_id).all()
  
  output=[]
  
  for q in todos:
    task_data={}
    task_data['id']=q.u_id
    task_data['title']=q.title
    task_data['description']=q.desc
    task_data['status']=q.status
    output.append(task_data)

  return jsonify({'tasks': output})
  
@app.route('/todo/<int:task_id>', methods=['GET'])
@token_required
def get_task(current_user,task_id):
  todo = TDA.query.filter_by(user_id=current_user.u_id, u_id=task_id ).first()
  
  if not todo:
    return jsonify({"message": "Somethings seems wrong, no todo againest id"})
  
  task_data={}
  task_data['id']=todo.u_id
  task_data['title']=todo.title
  task_data['description']=todo.desc
  task_data['status']=todo.status  

  return jsonify({ 'task': task_data })

@app.route('/todo', methods=['POST'])
@token_required
def create_task(current_user):
  data = request.get_json()
   
  count = len(TDA.query.filter_by(user_id=current_user.u_id).all())
  count=count+1
   
  new_todo = TDA(u_id=count, title=data['title'], status=False,desc= data['description'],user_id=current_user.u_id)
  
  new_todo.save()

  return jsonify({'message': 'Its time to do something, new todo added.....!'}), 201

@app.route('/todo/<int:task_id>', methods=['PUT'])
@token_required
def update_task(current_user, task_id):
  
  todo = TDA.query.filter_by(user_id=current_user.u_id, u_id=task_id ).first()
  
  if not todo:
    return jsonify({"message": "Somethings seems wrong, no todo againest id"})

  todo.status=True
  todo.save()
  
  return jsonify({'task': 'Wao you did it, congrats.....!'})

@app.route('/todo/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
  
  todo = TDA.query.filter_by(user_id=current_user.u_id, u_id=task_id ).first()
  
  if not todo:
    return jsonify({"message": "Somethings seems wrong, no todo againest id"})
  
  todo.remove()

  return jsonify({'result': 'Task deleted successfully.....!'})

if __name__ == '__main__':
  app.run(debug=True, port=12345)