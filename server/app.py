#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

class Signup(Resource):
    def post(self):
        data = request.get_json()
        
        # Check for required fields
        if 'username' not in data or 'password' not in data:
            return {'error': 'Username and password are required'}, 422

        try:
            # Hash the password before saving
            hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
            user = User(
                username=data['username'],
                _password_hash=hashed_password,
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(), 201
        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already exists'}, 422
        except ValueError as e:
            db.session.rollback()
            return {'error': str(e)}, 422

class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id == session.get('user_id')).first()
        if user:
            return user.to_dict(), 200
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        if 'username' not in data or 'password' not in data:
            return {'error': 'Username and password are required'}, 422

        user = User.query.filter_by(username=data['username']).first()
        if user and bcrypt.check_password_hash(user._password_hash, data['password']):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session['user_id'] = None
            return {}, 204
        return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        if session.get('user_id'):
            recipes = Recipe.query.filter_by(user_id=session['user_id']).all()
            return [recipe.to_dict() for recipe in recipes], 200
        return {'error': 'Unauthorized'}, 401

    def post(self):
        if session.get('user_id'):
            data = request.get_json()
            recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=session['user_id']  # Set user_id from the session
            )
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(), 201
        return {'error': 'Unauthorized'}, 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)