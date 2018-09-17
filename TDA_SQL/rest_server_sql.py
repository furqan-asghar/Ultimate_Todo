# -*- coding: utf-8 -*-
"""
Created on Thu Aug 16 20:11:24 2018

@author: root
"""

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from functools import wraps
import os
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'todo.db')

db = SQLAlchemy(app)

class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  public_id = db.Column(db.String(50), unique=True)
  name = db.Column(db.String(50))
  password = db.Column(db.String(50))
  admin = db.Column(db.Boolean)
  
class TDA(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  title = db.Column(db.String(50))
  desc = db.Column(db.String(100))
  status = db.Column(db.Boolean)
  user_id = db.Column(db.Integer)


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
def get_one_user(public_id):
  
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
  
  if not current_user.admin:
    return jsonify({'Users': 'prohibited for underprivileged'})
  
  hashed_pass = generate_password_hash(data['password'], method='sha256')
  new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_pass, admin=False) 
  db.session.add(new_user)
  db.session.commit()
  return jsonify({'message' : 'New user added'})

@app.route('/user/<public_id>',methods=['PUT'])
@token_required
def promote_user(public_id,current_user):
  user = User.query.filter_by(public_id=public_id).first()
  
  if not current_user.admin:
    return jsonify({'Users': 'prohibited for underprivileged'})
  
  if not user:
    return jsonify({'message': 'User not found'})
  
  user.admin = True
  db.session.commit()
  return jsonify({'message': 'User Promoted'})

@app.route('/user/<public_id>',methods=['DELETE'])
@token_required
def delete_user(public_id,current_user):
  user = User.query.filter_by(public_id=public_id).first()
  
  if not current_user.admin:
    return jsonify({'Users': 'prohibited for underprivileged'})
  
  if not user:
    return jsonify({'message': 'User not found'})
  
  db.session.delete(user)
  db.session.commit()
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

@app.route('/todo', methods=['POST'])
@token_required
def create_task(current_user):

  data = request.get_json()
  
  new_todo = TDA(title=data['title'], status=False,desc= data['description'],user_id=current_user.id)
  db.session.add(new_todo)
  db.session.commit()
  
  return jsonify({'message': 'Its time to do something, new todo added.....!'}), 201

@app.route('/todo', methods=['GET'])
@token_required
def get_all_tasks(current_user):
  
  todos = TDA.query.filter_by(user_id=current_user.id).all()
  
  output=[]
  
  for q in todos:
    task_data={}
    task_data['id']=q.id
    task_data['title']=q.title
    task_data['description']=q.desc
    task_data['status']=q.status
    output.append(task_data)

  return jsonify({'tasks': output})
  
@app.route('/todo/<int:task_id>', methods=['GET'])
@token_required
def get_task(current_user,task_id):
  todo = TDA.query.filter_by(user_id=current_user.id, id=task_id ).first()
  
  if not todo:
    return jsonify({"message": "Somethings seems wrong, no todo againest id"})
  
  task_data={}
  task_data['id']=todo.id
  task_data['title']=todo.title
  task_data['description']=todo.desc
  task_data['status']=todo.status
#  output.append(data)
  
  

  return jsonify({ 'task': task_data })

@app.route('/todo/<int:task_id>', methods=['PUT'])
@token_required
def update_task(current_user, task_id):
  
  todo = TDA.query.filter_by(user_id=current_user.id, id=task_id ).first()
  
  if not todo:
    return jsonify({"message": "Somethings seems wrong, no todo againest id"})

  todo.status=True
  db.session.commit()
  
  return jsonify({'task': 'Wao you did it, congrats.....!'})

@app.route('/todo/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
  
  todo = TDA.query.filter_by(user_id=current_user.id, id=task_id ).first()
  
  if not todo:
    return jsonify({"message": "Somethings seems wrong, no todo againest id"})
  
  db.session.delete(todo)
  db.session.commit()

  return jsonify({'result': 'Task deleted successfully.....!'})

if __name__ == '__main__':
  app.run(debug=True, port=1234)