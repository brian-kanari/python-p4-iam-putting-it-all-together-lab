#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup',
        'login',
        'check_session'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401


class Signup(Resource):
    
    def post(self):

        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')
        image_url = request_json.get('image_url')
        bio = request_json.get('bio')

        user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )

        # the setter will encrypt this
        user.password_hash = password

        try:

            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return user.to_dict(), 201

        except IntegrityError:

            return {'error': '422 Unprocessable Entity'}, 422

class CheckSession(Resource):

    def get(self):
        
        user_id = session['user_id']
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        
        return {}, 401


class Login(Resource):
    
    def post(self):

        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')

        user = User.query.filter(User.username == username).first()

        if user:
            if user.authenticate(password):

                session['user_id'] = user.id
                return user.to_dict(), 200

        return {'error': '401 Unauthorized'}, 401

class Logout(Resource):

    def delete(self):

        session['user_id'] = None
        
        return {}, 204
        

class RecipeIndex(Resource):

    def get(self):
        # Retrieve the user by the session's user_id
        user = User.query.filter(User.id == session.get('user_id')).first()

        if user:
            return [recipe.to_dict() for recipe in user.recipes], 200
        else:
            return {'error': 'User not found'}, 404

    def post(self):
        request_json = request.get_json()

        title = request_json.get('title')
        instructions = request_json.get('instructions')
        minutes_to_complete = request_json.get('minutes_to_complete')

        # Validate input before proceeding
        if not title or not instructions or not minutes_to_complete:
            return {'error': 'Missing required fields: title, instructions, or minutes_to_complete'}, 400

        try:
            # Ensure the length of instructions is valid
            if len(instructions) < 50:
                raise ValueError("Instructions must be at least 50 characters long.")

            # Create the new recipe object
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session.get('user_id'),
            )

            # Add the recipe to the database
            db.session.add(recipe)
            db.session.commit()

            return recipe.to_dict(), 201

        except ValueError as ve:
            
            return {'error': str(ve)}, 422

        except IntegrityError:
            db.session.rollback()
            
            return {'error': 'Database integrity error. Could not process the request.'}, 400

        except Exception as e:
            db.session.rollback()
        
            return {'error': f'An unexpected error occurred: {str(e)}'}, 500


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)