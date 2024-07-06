#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')
        if not username or not password:
            return jsonify({'error': 'Please input a username and a password'}), 422

        new_user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )
        new_user.password_hash = password
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        return new_user.to_dict(), 201
    

class CheckSession(Resource):
    
    def get(self):
        user = User.query.filter(User.id == session.get('user_id')).first()
        if user:
            return jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }), 200
        else:
            return {'message': '401: Not Authorized'}, 401

class Login(Resource):
    
    def post(self):
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return {'message': 'Missing username or password'}, 400
            
            user = User.query.filter(User.username == username).first()

            if user and user.authenticate(password):
                session['user_id'] = user.id
                return jsonify({
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }), 200
            return {'message': '401: Not Authorized'}, 401
        except KeyError as e:
            return {'message': f'KeyError: {str(e)}'}, 400

class Logout(Resource):
    
    def delete(self):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        session.pop('user_id', None)

        return '', 401

class RecipeIndex(Resource):
    
    def get(self, id=None):
        user_id = session.get('user_id')
        if user_id is None:
            return {'error': 'Unauthorized'}, 401
        recipes = Recipe.query.all()
        return jsonify([
            {
                'id': recipe.id,
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': {
                    'id': recipe.user.id,
                    'username': recipe.user.username,
                    'image_url': recipe.user.image_url,
                    'bio': recipe.user.bio
                }
            } for recipe in recipes
        ]), 200
    
    def post(self):
        user_id = session.get('user_id')
        if user_id is None:
            return {'error': 'Unauthorized'}, 401
        
        data = request.get_json()
        title = data.get("title")
        instructions = data.get("instructions")
        minutes_to_complete = data.get("minutes_to_complete")

        if not title or not instructions or len(instructions) < 50:
            return jsonify({'message': 'Please enter a valid title, instructions, and minutes_to_complete'}), 422
        new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )

        db.session.add(new_recipe)
        db.session.commit()

        recipe_data = self.serialize_recipe(new_recipe)
        return jsonify(recipe_data), 201  

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)