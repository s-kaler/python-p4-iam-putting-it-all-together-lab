#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json = request.get_json()
        if 'username' not in json or 'password' not in json or 'image_url' not in json or 'bio' not in json:
            return {'error': 'Missing required fields'}, 422
        user = User(
            username=json['username']
        )
        user.password_hash = json['password']
        user.image_url = json['image_url']
        user.bio = json['bio']
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        
        user_id = session['user_id']
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        
        return {}, 401

class Login(Resource):
    def post(self):
        username = request.get_json()['username']
        user = User.query.filter(User.username == username).first()
        if user:
            password = request.get_json()['password']
            if user.authenticate(password):
                session['user_id'] = user.id
                return user.to_dict(), 200
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        if session['user_id']:
            session['user_id'] = None
            return {}, 204
        else:
            return {'error': 'User is not logged in'}, 401

class RecipeIndex(Resource):
    def get(self):
        if session['user_id']:
            recipes = Recipe.query.all()
            return [recipe.to_dict() for recipe in recipes], 200
        else:
            return {'error': 'User is not logged in'}, 401

    def post(self):
        if session['user_id']:
            json = request.get_json()
            if 'title' not in json or 'instructions' not in json or 'minutes_to_complete' not in json:
                return {'error': 'Missing required fields'}, 422
            try:
                recipe = Recipe(
                    title=json['title'],
                    instructions=json['instructions'],
                    minutes_to_complete=json['minutes_to_complete'],
                    user_id=session['user_id']
                )
                db.session.add(recipe)
                db.session.commit()
                return recipe.to_dict(), 201
            except ValueError:
                return {'error': 'Failed to create recipe'}, 422
        else:
            return {'error': 'User is not logged in'}, 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)